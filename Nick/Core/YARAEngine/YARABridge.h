// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

// YARABridge.h — Bridging header exposing the vendored libyara C API to Swift.
//
// Import this file via the Xcode "Objective-C Bridging Header" build setting
// on the Nick target. It provides both the raw libyara API and a set of
// accessor helpers that work around DECLARE_REFERENCE anonymous unions that
// Swift cannot access directly.

#ifndef YARABridge_h
#define YARABridge_h

#include <string.h>
#include <stdlib.h>

// SECURITY: yara.h is vendored at a pinned version (v4.5.2).
// Never replace with a system-installed header that could be tampered with.
// Use the angle-bracket form so clang resolves via HEADER_SEARCH_PATHS
// ($(SRCROOT)/Nick/Core/YARAEngine/Vendor/include) rather than relative to
// whatever working directory the PCH compilation step uses. Both local and CI
// builds have the search path set; the relative-path form can silently break
// when Xcode compiles the bridging header from a derived-data staging location.
#include <yara.h>

// ---------------------------------------------------------------------------
// C accessor helpers — Swift cannot traverse DECLARE_REFERENCE anonymous
// unions (e.g. rule->identifier, rule->tags, meta->identifier, meta->string).
// These thin inline functions provide type-safe access from Swift.
// ---------------------------------------------------------------------------

/// Returns the null-terminated rule identifier string.
static inline const char* nick_rule_identifier(const YR_RULE* rule) {
    return rule->identifier;
}

/// Returns the pointer to the first tag in the rule's concatenated-tags block.
/// Tags are stored as sequential null-terminated C strings, terminated by an
/// empty string (\0). Iterate with:
///   ptr = nick_rule_first_tag(rule)
///   while (*ptr != 0) { use ptr; ptr += strlen(ptr) + 1; }
static inline const char* nick_rule_first_tag(const YR_RULE* rule) {
    return rule->tags;
}

/// Returns the pointer to the first YR_META in the rule's metadata list,
/// or NULL when there are no metadata entries.
static inline const YR_META* nick_rule_first_meta(const YR_RULE* rule) {
    return rule->metas;
}

/// Returns true when `meta` is the last metadata entry in its rule.
static inline int nick_meta_is_last(const YR_META* meta) {
    return (meta->flags & META_FLAGS_LAST_IN_RULE) != 0;
}

/// Returns the null-terminated metadata key (identifier).
static inline const char* nick_meta_identifier(const YR_META* meta) {
    return meta->identifier;
}

/// Returns the null-terminated metadata string value, or NULL if the
/// metadata type is not META_TYPE_STRING.
static inline const char* nick_meta_string_value(const YR_META* meta) {
    if (meta->type == META_TYPE_STRING) {
        return meta->string;
    }
    return NULL;
}

/// Returns the integer value for META_TYPE_INTEGER / META_TYPE_BOOLEAN entries.
static inline int64_t nick_meta_integer_value(const YR_META* meta) {
    return meta->integer;
}

/// Returns the metadata type (META_TYPE_STRING, META_TYPE_INTEGER,
/// META_TYPE_BOOLEAN).
static inline int32_t nick_meta_type(const YR_META* meta) {
    return meta->type;
}

#endif /* YARABridge_h */
