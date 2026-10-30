/* SPDX-License-Identifier: GPL-2.0-or-later
 * Experimental strongSwan 6.0.1 plugin: request protected IPv4 subnets and
 * constrain local CHILD_SA installation to their intersection with peer TS.
 * Uses the attribute-handler/listener APIs illustrated by upstream Unity.
 */
#include <daemon.h>
#include <threading/mutex.h>
#include "subnet.h"
#ifdef FGR_MANAGER_PLUGIN
#include <ifaddrs.h>
#include <net/if.h>
#endif

#define MAX_SUBNETS 256
#ifdef FGR_MANAGER_PLUGIN
#define PLUGIN_NAME "fortigate-manager-subnets"
#else
#define PLUGIN_NAME "fortigate-subnets"
#endif
typedef struct subnet_state_t subnet_state_t;
struct subnet_state_t {
    uint32_t id;
    unsigned count;
    bool invalid;
    struct { uint32_t network; unsigned prefix; } subnets[MAX_SUBNETS];
    subnet_state_t *next;
};
typedef struct {
    plugin_t plugin;
    attribute_handler_t handler;
    listener_t listener;
    mutex_t *mutex;
    subnet_state_t *states;
} private_plugin_t;

static bool scoped(ike_sa_t *sa)
{
#ifdef FGR_MANAGER_PLUGIN
    const char *name;
    size_t n;
    if (!sa) { return FALSE; }
    name = sa->get_name(sa);
    if (!name || !strpfx(name, "fgr-")) { return FALSE; }
    name += 4;
    n = strspn(name, "0123456789");
    if (!n || n > 10 || name[n] != '-') { return FALSE; }
    name += n + 1;
    n = strspn(name, "0123456789abcdef");
    if (n != 32 || (name[n] && !streq(name + n, "-lan") && !streq(name + n, "-all"))) { return FALSE; }
    return sa->get_version(sa) == IKEV2 &&
           sa->has_condition(sa, COND_ORIGINAL_INITIATOR);
#else
    return sa && sa->get_version(sa) == IKEV2 &&
           sa->has_condition(sa, COND_ORIGINAL_INITIATOR) &&
           streq(sa->get_name(sa), "fortigate");
#endif
}

/* Caller holds mutex. Entries are bound to unique IKE_SA IDs, not addresses. */
static subnet_state_t *state(private_plugin_t *this, uint32_t id, bool create)
{
    subnet_state_t *s;
    for (s = this->states; s; s = s->next) {
        if (s->id == id) { return s; }
    }
    if (!create) { return NULL; }
    s = calloc(1, sizeof(*s));
    if (!s) { return NULL; }
    s->id = id;
    s->next = this->states;
    this->states = s;
    return s;
}

METHOD(attribute_handler_t, handle, bool,
    attribute_handler_t *handler, ike_sa_t *sa,
    configuration_attribute_type_t type, chunk_t data)
{
    private_plugin_t *this = (void*)((char*)handler - offsetof(private_plugin_t, handler));
    subnet_state_t *s;
    uint32_t network;
    unsigned prefix, i;
    if (!scoped(sa) || type != INTERNAL_IP4_SUBNET) { return FALSE; }
    this->mutex->lock(this->mutex);
    s = state(this, sa->get_unique_id(sa), TRUE);
    if (!s) {
        this->mutex->unlock(this->mutex);
        return FALSE;
    }
    if (!decode_subnet(data.ptr, data.len, &network, &prefix)) {
        s->invalid = TRUE;
        DBG1(DBG_CFG, "fortigate-subnets: rejected invalid or default subnet attribute");
    } else {
        for (i = 0; i < s->count; i++) {
            if (s->subnets[i].network == network && s->subnets[i].prefix == prefix) { break; }
        }
        if (i == s->count) {
            if (s->count == MAX_SUBNETS) { s->invalid = TRUE; }
            else {
                s->subnets[s->count].network = network;
                s->subnets[s->count++].prefix = prefix;
                DBG1(DBG_CFG, "fortigate-subnets: accepted protected IPv4 subnet (/%u)", prefix);
            }
        }
    }
    this->mutex->unlock(this->mutex);
    return TRUE;
}

METHOD(attribute_handler_t, release, void,
    attribute_handler_t *handler, ike_sa_t *sa,
    configuration_attribute_type_t type, chunk_t data)
{
    /* IKE_DESTROYING clears the entire SA cache; rekey migrates it first. */
}

typedef struct { enumerator_t public; bool done; } request_t;
METHOD(enumerator_t, enumerate_request, bool, request_t *this, va_list args)
{
    configuration_attribute_type_t *type;
    chunk_t *data;
    VA_ARGS_VGET(args, type, data);
    if (this->done) { return FALSE; }
    this->done = TRUE;
    *type = INTERNAL_IP4_SUBNET;
    *data = chunk_empty;
    return TRUE;
}

METHOD(attribute_handler_t, requests, enumerator_t*,
    attribute_handler_t *handler, ike_sa_t *sa, linked_list_t *vips)
{
    request_t *request;
    if (!scoped(sa)) { return enumerator_create_empty(); }
    INIT(request,
        .public = {
            .enumerate = enumerator_enumerate_default,
            .venumerate = _enumerate_request,
            .destroy = (void*)free,
        },
    );
    DBG1(DBG_CFG, "fortigate-subnets: requesting INTERNAL_IP4_SUBNET");
    return &request->public;
}

static void insert_unique(linked_list_t *list, traffic_selector_t *candidate)
{
    enumerator_t *enumerator = list->create_enumerator(list);
    traffic_selector_t *existing;
    while (enumerator->enumerate(enumerator, &existing)) {
        if (candidate->is_contained_in(candidate, existing)) {
            candidate->destroy(candidate);
            enumerator->destroy(enumerator);
            return;
        }
        if (existing->is_contained_in(existing, candidate)) {
            list->remove_at(list, enumerator);
            existing->destroy(existing);
        }
    }
    enumerator->destroy(enumerator);
    list->insert_last(list, candidate);
}

#ifdef FGR_MANAGER_PLUGIN
/* Emit exact CIDR fragments; a non-CIDR range must not install a broader route. */
static bool append_range(linked_list_t *list, traffic_selector_t *orig,
                         uint64_t first, uint64_t last)
{
    while (first <= last) {
        unsigned bits = first ? __builtin_ctz((uint32_t)first) : 32;
        uint64_t size;
        uint32_t a, b;
        traffic_selector_t *ts;
        while ((1ULL << bits) > last - first + 1) { bits--; }
        size = 1ULL << bits;
        a = htonl(first); b = htonl(first + size - 1);
        ts = traffic_selector_create_from_bytes(orig->get_protocol(orig), TS_IPV4_ADDR_RANGE,
            chunk_create((void*)&a, 4), orig->get_from_port(orig),
            chunk_create((void*)&b, 4), orig->get_to_port(orig));
        if (!ts || list->get_count(list) >= 4096) {
            if (ts) { ts->destroy(ts); }
            return FALSE;
        }
        list->insert_last(list, ts);
        first += size;
    }
    return TRUE;
}

static bool exclude_range(linked_list_t *list, uint32_t first, uint32_t last)
{
    linked_list_t *out = linked_list_create();
    traffic_selector_t *ts;
    bool ok = TRUE;
    while (list->remove_first(list, (void**)&ts) == SUCCESS) {
        uint32_t a, b;
        chunk_t from = ts->get_from_address(ts), to = ts->get_to_address(ts);
        if (from.len != 4 || to.len != 4) { ts->destroy(ts); ok = FALSE; continue; }
        memcpy(&a, from.ptr, 4); memcpy(&b, to.ptr, 4);
        a = ntohl(a); b = ntohl(b);
        if (last < a || first > b) { out->insert_last(out, ts); continue; }
        if (first > a) { ok = append_range(out, ts, a, (uint64_t)first - 1) && ok; }
        if (last < b) { ok = append_range(out, ts, (uint64_t)last + 1, b) && ok; }
        ts->destroy(ts);
    }
    while (out->remove_first(out, (void**)&ts) == SUCCESS) { list->insert_last(list, ts); }
    out->destroy(out);
    return ok;
}

static bool preserve_local_lan(linked_list_t *list)
{
    struct ifaddrs *addresses, *entry;
    bool ok = TRUE;
    if (getifaddrs(&addresses) != 0) { return FALSE; }
    for (entry = addresses; entry && ok; entry = entry->ifa_next) {
        uint32_t addr, mask;
        if (!entry->ifa_addr || !entry->ifa_netmask || entry->ifa_addr->sa_family != AF_INET ||
            !(entry->ifa_flags & IFF_UP) || !(entry->ifa_flags & IFF_RUNNING) ||
            (entry->ifa_flags & (IFF_LOOPBACK | IFF_POINTOPOINT))) { continue; }
        addr = ntohl(((struct sockaddr_in*)entry->ifa_addr)->sin_addr.s_addr);
        mask = ntohl(((struct sockaddr_in*)entry->ifa_netmask)->sin_addr.s_addr);
        if (!mask) { continue; }
        ok = exclude_range(list, addr & mask, (addr & mask) | ~mask);
    }
    freeifaddrs(addresses);
    return ok;
}
#endif

METHOD(listener_t, narrow, bool,
    listener_t *listener, ike_sa_t *sa, child_sa_t *child,
    narrow_hook_t hook, linked_list_t *local, linked_list_t *remote)
{
    private_plugin_t *this = (void*)((char*)listener - offsetof(private_plugin_t, listener));
    subnet_state_t *s;
    linked_list_t *selected;
    traffic_selector_t *original, *advertised, *subset;
    enumerator_t *enumerator;
    unsigned i;
    char cidr[32], addr[INET_ADDRSTRLEN];
    struct in_addr ip;
    if (!scoped(sa) || (hook != NARROW_INITIATOR_POST_NOAUTH &&
        hook != NARROW_INITIATOR_POST_AUTH && hook != NARROW_RESPONDER_POST)) {
        return TRUE;
    }
    selected = linked_list_create();
    this->mutex->lock(this->mutex);
    s = state(this, sa->get_unique_id(sa), FALSE);
    if (s && !s->invalid && s->count) {
        for (i = 0; i < s->count; i++) {
            ip.s_addr = htonl(s->subnets[i].network);
            inet_ntop(AF_INET, &ip, addr, sizeof(addr));
            snprintf(cidr, sizeof(cidr), "%s/%u", addr, s->subnets[i].prefix);
            advertised = traffic_selector_create_from_cidr(cidr, 0, 0, 65535);
            if (!advertised) { continue; }
            enumerator = remote->create_enumerator(remote);
            while (enumerator->enumerate(enumerator, &original)) {
                subset = original->get_subset(original, advertised);
                if (subset) { insert_unique(selected, subset); }
            }
            enumerator->destroy(enumerator);
            advertised->destroy(advertised);
        }
    }
    this->mutex->unlock(this->mutex);
#ifdef FGR_MANAGER_PLUGIN
    {
        const char *name = sa->get_name(sa);
        size_t len = strlen(name);
        if (len >= 4 && streq(name + len - 4, "-lan") && !preserve_local_lan(selected)) {
            while (selected->remove_first(selected, (void**)&subset) == SUCCESS) { subset->destroy(subset); }
            DBG1(DBG_CFG, "fortigate-manager-subnets: local LAN enumeration failed; refusing child tunnel");
        }
    }
#endif
    while (remote->remove_first(remote, (void**)&original) == SUCCESS) {
        original->destroy(original);
    }
    while (selected->remove_first(selected, (void**)&subset) == SUCCESS) {
        remote->insert_last(remote, subset);
    }
    selected->destroy(selected);
    if (!remote->get_count(remote)) {
        DBG1(DBG_CFG, "fortigate-subnets: refusing CHILD_SA without usable advertised IPv4 subnets");
    } else {
        DBG1(DBG_CFG, "fortigate-subnets: installed selector restriction to %u subnet intersections",
             remote->get_count(remote));
    }
    return TRUE;
}

METHOD(listener_t, state_change, bool,
    listener_t *listener, ike_sa_t *sa, ike_sa_state_t change)
{
    private_plugin_t *this = (void*)((char*)listener - offsetof(private_plugin_t, listener));
    subnet_state_t **p, *old;
    if (change != IKE_DESTROYING) { return TRUE; }
    this->mutex->lock(this->mutex);
    for (p = &this->states; *p; p = &(*p)->next) {
        if ((*p)->id == sa->get_unique_id(sa)) {
            old = *p; *p = old->next; free(old); break;
        }
    }
    this->mutex->unlock(this->mutex);
    return TRUE;
}

METHOD(listener_t, rekey, bool,
    listener_t *listener, ike_sa_t *old, ike_sa_t *new)
{
    private_plugin_t *this = (void*)((char*)listener - offsetof(private_plugin_t, listener));
    subnet_state_t *s;
    this->mutex->lock(this->mutex);
    s = state(this, old->get_unique_id(old), FALSE);
    if (s) { s->id = new->get_unique_id(new); }
    this->mutex->unlock(this->mutex);
    return TRUE;
}

METHOD(plugin_t, get_name, char*, private_plugin_t *this) { return PLUGIN_NAME; }

static bool plugin_cb(private_plugin_t *this, plugin_feature_t *feature, bool reg, void *data)
{
    if (reg) {
        charon->attributes->add_handler(charon->attributes, &this->handler);
        charon->bus->add_listener(charon->bus, &this->listener);
    } else {
        charon->bus->remove_listener(charon->bus, &this->listener);
        charon->attributes->remove_handler(charon->attributes, &this->handler);
    }
    return TRUE;
}

METHOD(plugin_t, get_features, int, private_plugin_t *this, plugin_feature_t **features)
{
    static plugin_feature_t list[] = {
        PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
        PLUGIN_PROVIDE(CUSTOM, PLUGIN_NAME),
    };
    *features = list;
    return countof(list);
}

METHOD(plugin_t, destroy, void, private_plugin_t *this)
{
    subnet_state_t *next;
    while (this->states) {
        next = this->states->next; free(this->states); this->states = next;
    }
    this->mutex->destroy(this->mutex);
    free(this);
}

#ifdef FGR_MANAGER_PLUGIN
plugin_t *fortigate_manager_subnets_plugin_create(void)
#else
plugin_t *fortigate_subnets_plugin_create(void)
#endif
{
    private_plugin_t *this;
    INIT(this,
        .plugin = { .get_name = _get_name, .get_features = _get_features, .destroy = _destroy },
        .handler = { .handle = _handle, .release = _release, .create_attribute_enumerator = _requests },
        .listener = { .narrow = _narrow, .ike_state_change = _state_change, .ike_rekey = _rekey },
        .mutex = mutex_create(MUTEX_TYPE_DEFAULT),
    );
    return &this->plugin;
}
