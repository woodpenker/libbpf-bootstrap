#ifndef __LEGACY_CODE_HELPER_H
#define __LEGACY_CODE_HELPER_H
#define __JOIN(x,y) x##y
#define __X(x) x
#define __NAME(name) __JOIN(legacy_, name)
#ifdef BPF_NO_GLOBAL_DATA

#define DEFINE_ARG(name, arg_type) \
struct {\
	__uint(type, BPF_MAP_TYPE_ARRAY);\
	__uint(max_entries, 1);\
	__type(key, __u32);\
	__type(value, arg_type);\
} __NAME(name) SEC(".maps")

#define READ_ARG_INTO(name) \
do{\
__u32 key = 0;\
typeof(__X(name)) *dest;\
dest = bpf_map_lookup_elem(&__NAME(name), &key);\
if(dest) __X(name) = *dest;\
}while(0)


#define SET_ARG(skel, name, value) \
({\
__u32 idx = 0;\
int _err;\
_err = bpf_map__update_elem(skel->maps.__NAME(name), &idx, sizeof(idx), &value, sizeof(value), BPF_ANY);\
_err;\
})

#define DEFINE_MUT_ARG(name, arg_type, arg_default) \
DEFINE_ARG(name, arg_type)

#define DEFINE_RO_ARG(name, arg_type, arg_default) \
DEFINE_ARG(name, arg_type)

#define SET_MUT_ARG(skel, name, value) \
SET_ARG(skel, name, value)

#define SET_RO_ARG(skel, name, value) \
SET_ARG(skel, name, value)

#else

#define DEFINE_RO_ARG(name, arg_type, arg_default) \
const volatile arg_type __NAME(name) = arg_default

#define READ_ARG_INTO(name) \
name = __NAME(name)

#define SET_RO_ARG(skel, name, value) \
({\
skel->rodata->__NAME(name) = value; \
0;\
})

#define DEFINE_MUT_ARG(name, arg_type, arg_default) \
arg_type __NAME(name) = arg_default

#define SET_MUT_ARG(skel, name, value) \
({\
skel->bss->__NAME(name) = value; \
0;\
})

#define DEFINE_ARG(name, arg_type) \
arg_type __NAME(name)

#define SET_ARG(skel, name, value) \
({\
skel->data->__NAME(name) = value; \
0;\
})

#endif // BPF_NO_GLOBAL_DATA
#endif // __LEGACY_CODE_HELPER_H