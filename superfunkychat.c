#include <epan/packet.h>

#define SUPERFUNKYCHAT_PORT 12345

static int proto_superfunkychat = -1;

static int dissect_superfunkychat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SuperFunkyChat");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    return tvb_captured_length(tvb);
}


void proto_register_superfunkychat() {
  proto_superfunkychat = proto_register_protocol("SuperFunkyChat", "SF Chat", "sfc");
}

void proto_reg_handoff_superfunkychat(void)
{
    static dissector_handle_t sfc_handle;

    sfc_handle = create_dissector_handle(dissect_superfunkychat, proto_superfunkychat);
    dissector_add_uint("udp.port", SUPERFUNKYCHAT_PORT, sfc_handle);
}

