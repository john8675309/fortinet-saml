/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include "fortigate_subnets.c"
#ifdef FGR_MANAGER_PLUGIN
#define TEST_CONNECTION "fgr-1000-0123456789abcdef0123456789abcdef"
#define CREATE_PLUGIN fortigate_manager_subnets_plugin_create
#else
#define TEST_CONNECTION "fortigate"
#define CREATE_PLUGIN fortigate_subnets_plugin_create
#endif

typedef struct {
    ike_sa_t public;
    uint32_t id;
    ike_version_t version;
    bool original;
    char *name;
} fake_sa_t;
static uint32_t fake_id(ike_sa_t *sa) { return ((fake_sa_t*)sa)->id; }
static ike_version_t fake_version(ike_sa_t *sa) { return ((fake_sa_t*)sa)->version; }
static bool fake_condition(ike_sa_t *sa, ike_condition_t condition) { return ((fake_sa_t*)sa)->original; }
static char *fake_name(ike_sa_t *sa) { return ((fake_sa_t*)sa)->name; }
static fake_sa_t fake(uint32_t id)
{
    fake_sa_t sa = {
        .public = { .get_unique_id = fake_id, .get_version = fake_version,
                    .has_condition = fake_condition, .get_name = fake_name },
        .id = id, .version = IKEV2, .original = TRUE, .name = TEST_CONNECTION,
    };
    return sa;
}
static linked_list_t *selectors(char *cidr)
{
    linked_list_t *list = linked_list_create();
    traffic_selector_t *ts = traffic_selector_create_from_cidr(cidr, 0, 0, 65535);
    assert(ts);
    list->insert_last(list, ts);
    return list;
}
static void clear_selectors(linked_list_t *list)
{
    list->destroy_offset(list, offsetof(traffic_selector_t, destroy));
}
static bool add(private_plugin_t *plugin, fake_sa_t *sa, uint8_t bytes[8])
{
    return plugin->handler.handle(&plugin->handler, &sa->public,
                                  INTERNAL_IP4_SUBNET, chunk_create(bytes, 8));
}
static void assert_only(linked_list_t *list, char *cidr)
{
    traffic_selector_t *got, *expected;
    assert(list->get_count(list) == 1);
    assert(list->get_first(list, (void**)&got) == SUCCESS);
    expected = traffic_selector_create_from_cidr(cidr, 0, 0, 65535);
    assert(got->equals(got, expected));
    expected->destroy(expected);
}
static void restrict_ts(private_plugin_t *plugin, fake_sa_t *sa, linked_list_t *remote)
{
    linked_list_t *local = linked_list_create();
    assert(plugin->listener.narrow(&plugin->listener, &sa->public, NULL,
                                  NARROW_INITIATOR_POST_NOAUTH, local, remote));
    clear_selectors(local);
}
int main(void)
{
    uint8_t subnet[8] = {198, 51, 100, 99, 255, 255, 255, 0};
    uint8_t second[8] = {203, 0, 113, 0, 255, 255, 255, 0};
    uint8_t invalid[8] = {198, 51, 0, 0, 255, 0, 255, 0};
    uint8_t zero[8] = {0};
    uint32_t net;
    unsigned prefix, i;
    fake_sa_t sa = fake(1), other = fake(2), missing = fake(3);
    plugin_t *public;
    private_plugin_t *plugin;
    linked_list_t *list, *vips;
    enumerator_t *request;
    configuration_attribute_type_t type;
    chunk_t data;
    daemon_t daemon = {0};
    assert(library_init(NULL, "fortigate-subnets-test"));
    charon = &daemon;
    daemon.bus = bus_create();
    public = CREATE_PLUGIN();
    plugin = (void*)public;
    assert(decode_subnet(subnet, 8, &net, &prefix));
    assert(net == 0xc6336400 && prefix == 24);
    assert(!decode_subnet(invalid, 8, &net, &prefix));
    assert(!decode_subnet(zero, 8, &net, &prefix));
    assert(!decode_subnet(NULL, 8, &net, &prefix));
    for (i = 0; i < 8; i++) { assert(!decode_subnet(subnet, i, &net, &prefix)); }
    assert(!decode_subnet(subnet, 9, &net, &prefix));

    vips = linked_list_create();
    request = plugin->handler.create_attribute_enumerator(&plugin->handler, &sa.public, vips);
    assert(request->enumerate(request, &type, &data));
    assert(type == INTERNAL_IP4_SUBNET && data.len == 0);
    assert(!request->enumerate(request, &type, &data));
    request->destroy(request);
    assert(add(plugin, &sa, subnet));
    assert(add(plugin, &sa, subnet)); /* repeated attributes are deduplicated */
    list = selectors("0.0.0.0/0");
    restrict_ts(plugin, &sa, list);
    assert_only(list, "198.51.100.0/24");
    clear_selectors(list);

    assert(add(plugin, &sa, second));
    list = selectors("0.0.0.0/0");
    restrict_ts(plugin, &sa, list);
    assert(list->get_count(list) == 2);
    clear_selectors(list);
    list = selectors("198.51.100.128/25"); /* never expand peer-selected TS */
    restrict_ts(plugin, &sa, list);
    assert_only(list, "198.51.100.128/25");
    clear_selectors(list);
    list = selectors("192.0.2.0/24");
    restrict_ts(plugin, &sa, list);
    assert(!list->get_count(list));
    clear_selectors(list);

    /* Overlapping advertised networks must not yield duplicate policies. */
    list = linked_list_create();
    insert_unique(list, traffic_selector_create_from_cidr("198.51.100.0/24", 0, 0, 65535));
    insert_unique(list, traffic_selector_create_from_cidr("198.51.100.0/23", 0, 0, 65535));
    insert_unique(list, traffic_selector_create_from_cidr("198.51.100.0/24", 0, 0, 65535));
    assert_only(list, "198.51.100.0/23");
    clear_selectors(list);

#ifdef FGR_MANAGER_PLUGIN
    /* Local LAN exclusion must leave exact CIDRs and preserve selectors. */
    list = selectors("198.51.100.0/24");
    assert(exclude_range(list, 0xc6336400, 0xc633647f));
    assert_only(list, "198.51.100.128/25");
    clear_selectors(list);
    list = selectors("198.51.100.0/24");
    assert(exclude_range(list, 0xc6336400, 0xc63364ff));
    assert(!list->get_count(list));
    clear_selectors(list);
    list = selectors("198.51.100.0/24");
    assert(exclude_range(list, 0xc0000200, 0xc00002ff));
    assert_only(list, "198.51.100.0/24");
    clear_selectors(list);
    other.name = "fgr-1000-not-a-profile";
    assert(!add(plugin, &other, subnet));
    other.name = "fortigate";
    assert(!add(plugin, &other, subnet));
    other.name = TEST_CONNECTION;
#endif

    list = selectors("0.0.0.0/0"); /* no reply must not become a full tunnel */
    restrict_ts(plugin, &missing, list);
    assert(!list->get_count(list));
    clear_selectors(list);
    assert(add(plugin, &missing, invalid));
    assert(add(plugin, &missing, subnet));
    list = selectors("0.0.0.0/0");
    restrict_ts(plugin, &missing, list);
    assert(!list->get_count(list));
    clear_selectors(list);

    other.name = "unrelated";
    assert(!add(plugin, &other, subnet));
    list = selectors("0.0.0.0/0");
    restrict_ts(plugin, &other, list);
    assert_only(list, "0.0.0.0/0");
    clear_selectors(list);
    other.name = TEST_CONNECTION;
    other.version = IKEV1;
    request = plugin->handler.create_attribute_enumerator(&plugin->handler, &other.public, vips);
    assert(!request->enumerate(request, &type, &data));
    request->destroy(request);
    other.version = IKEV2;
    other.original = FALSE;
    assert(!add(plugin, &other, subnet));
    other.original = TRUE;
    plugin->listener.ike_rekey(&plugin->listener, &sa.public, &other.public);
    plugin->listener.ike_state_change(&plugin->listener, &sa.public, IKE_DESTROYING);
    list = selectors("0.0.0.0/0");
    restrict_ts(plugin, &other, list);
    assert(list->get_count(list) == 2);
    clear_selectors(list);
    plugin->listener.ike_state_change(&plugin->listener, &other.public, IKE_DESTROYING);
    list = selectors("0.0.0.0/0");
    restrict_ts(plugin, &other, list);
    assert(!list->get_count(list));
    clear_selectors(list);
    vips->destroy(vips);
    public->destroy(public);
    /* Exercise the actual shared object and installed library plugin loader. */
    daemon.attributes = attribute_manager_create();
    lib->plugins->add_path(lib->plugins, ".");
    lib->settings->set_bool(lib->settings, "%s.load_modular", TRUE, lib->ns);
    lib->settings->set_bool(lib->settings, "%s.plugins.%s!.load", TRUE, lib->ns, PLUGIN_NAME);
    assert(lib->plugins->load(lib->plugins, ""));
    assert(strstr(lib->plugins->loaded_plugins(lib->plugins), PLUGIN_NAME));
    lib->plugins->unload(lib->plugins);
    lib->settings->set_bool(lib->settings, "%s.plugins.%s!.load", FALSE, lib->ns, PLUGIN_NAME);
    lib->settings->set_bool(lib->settings, "%s.plugins.fortigate-subnets-missing!.load", TRUE, lib->ns);
    assert(!lib->plugins->load(lib->plugins, ""));
    lib->plugins->unload(lib->plugins);
    daemon.attributes->destroy(daemon.attributes);
    daemon.bus->destroy(daemon.bus);
    charon = NULL;
    library_deinit();
    puts("PASS: requests, subnet decoding, masks, deduplication, multiple subnets, intersections, fail-closed behavior, scope, rekey and cleanup");
    return 0;
}
