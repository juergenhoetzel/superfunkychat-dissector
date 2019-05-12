#define WS_BUILD_DLL
#include <epan/packet.h>
#include <epan/proto.h>
#include <ws_attributes.h>
#include <ws_symbol_export.h>
#include <ws_version.h>

#define CHAT_PORT 12345
#define DATA_OFFSET 5
#define MESSAGE_CMD 3

#ifndef VERSION
#define VERSION "0.0.1"
#endif

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

static int proto_chat = -1;
static int hf_chat_command = -1;
static int hf_chat_chksum = -1;
static int hf_chat_data = -1;

static int hf_chat_username = -1;
static int hf_chat_message = -1;

static gint ett_chat = -1;

static int dissect_chat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Chat");
  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo, COL_INFO);
  /* No other protocol encoded here */
  proto_item *ti = proto_tree_add_item(tree, proto_chat, tvb, 0, -1, ENC_NA);
  proto_tree *foo_tree = proto_item_add_subtree(ti, ett_chat);
  proto_tree_add_item(foo_tree, hf_chat_command, tvb, 4, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(foo_tree, hf_chat_chksum, tvb, 0, 4, ENC_BIG_ENDIAN);
  proto_tree *data_tree = proto_tree_add_item(foo_tree, hf_chat_data, tvb, DATA_OFFSET, -1, ENC_BIG_ENDIAN);
  proto_tree *sub_tree = proto_item_add_subtree(data_tree, 0);
  gint cmd = tvb_get_guint8(tvb, 4);
  if (cmd == MESSAGE_CMD) {
    int offset = DATA_OFFSET;
    int len = tvb_get_gint8(tvb, offset);
    char *username = (char *)wmem_alloc(wmem_packet_scope(), len + 1);
    tvb_memcpy(tvb, (guint8 *)username, offset + 1, len);
    username[len] = '\0';
    proto_tree_add_string(sub_tree, hf_chat_username, tvb, offset, len + 1, username);

    offset = offset + len + 1;
    len = tvb_get_gint8(tvb, offset);
    char *message = (char *)wmem_alloc(wmem_packet_scope(), len + 1);
    tvb_memcpy(tvb, (guint8 *)message, offset + 1, len);
    message[len] = '\0';
    proto_tree_add_string(sub_tree, hf_chat_message, tvb, offset, len + 1, message);
  }
  return tvb_captured_length(tvb);
}

void proto_register_chat() {
  static hf_register_info hf[] = {
      {&hf_chat_command, {"Command", "chat.command", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
      {&hf_chat_chksum, {"Checksum", "chat.chksum", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_chat_data, {"Data", "chat.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
      {&hf_chat_username, {"Username", "chat.username", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
      {&hf_chat_message, {"Message", "chat.message", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}}};
  /* Setup protocol subtree array */
  static gint *ett[] = {&ett_chat};
  proto_chat = proto_register_protocol("Chat", "SF Chat", "sfc");
  proto_register_field_array(proto_chat, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_chat() {
  static dissector_handle_t sfc_handle;

  sfc_handle = create_dissector_handle(dissect_chat, proto_chat);
  dissector_add_uint("udp.port", CHAT_PORT, sfc_handle);
}

void plugin_register() {
  static proto_plugin plug;
  plug.register_protoinfo = proto_register_chat;
  plug.register_handoff = proto_reg_handoff_chat; /* or NULL */
  proto_register_plugin(&plug);
}
