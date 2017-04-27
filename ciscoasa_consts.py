# --
# File: ciscoasa_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Json keys
CISCOASA_JSON_DIRECTION = "direction"
CISCOASA_JSON_ACCESS_LIST = "access-list"
CISCOASA_JSON_INTERFACE = "interface"
CISCOASA_JSON_LINE = "line"
CISCOASA_JSON_SRC_MASK = "src_mask"
CISCOASA_JSON_DEST_MASK = "dest_mask"
CISCOASA_JSON_DEST = "dest"
CISCOASA_JSON_SRC = "src"
CISCOASA_JSON_IP_USERNAME = "username"

# Success/Error messages
CISCOASA_ERR_CMD_EXEC = "Command execution failed"
CISCOASA_ERR_ASA_SRC_DEST_ANY = "Both Source and Dest can't be any"
CISCOASA_ERR_ASA_INVALID_DATA_ACCESS_GROUP = "Invalid data returned while querying for access-group"
CISCOASA_ERR_ASA_SSH_CONNECTION_FAILED = "Could not establish ssh connection to ASA device"
CISCOASA_SUCC_ASA_FOUND_ACCESS_LIST = "Found access-list"
CISCOASA_ERR_ASA_DUPLICATE_ACCESS_LIST = "Found an access-list named '{present_acl_name}' configured for the given interface '{intf}' and direction '{direction}', can't overwrite it with the given access-list '{acl_name}'. Please check the configuration"  # noqa
CISCOASA_SUCC_ASA_ACCESS_LIST_NOT_FOUND = "Access list not found"
CISCOASA_MSG_FROM_DEVICE = "Message from device:\n"

# Progress messages
CISCOASA_PROG_ACCESS_LIST_VALIDATED = "Access List validated"
CISCOASA_PROG_GOT_TEXT = "Got text from device =  '{}'"
