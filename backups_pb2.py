# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: backups.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='backups.proto',
  package='signal',
  syntax='proto2',
  serialized_options=b'\n!org.thoughtcrime.securesms.backupB\014BackupProtos',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\rbackups.proto\x12\x06signal\"\xe2\x01\n\x0cSqlStatement\x12\x11\n\tstatement\x18\x01 \x01(\t\x12\x35\n\nparameters\x18\x02 \x03(\x0b\x32!.signal.SqlStatement.SqlParameter\x1a\x87\x01\n\x0cSqlParameter\x12\x16\n\x0estringParamter\x18\x01 \x01(\t\x12\x18\n\x10integerParameter\x18\x02 \x01(\x04\x12\x17\n\x0f\x64oubleParameter\x18\x03 \x01(\x01\x12\x15\n\rblobParameter\x18\x04 \x01(\x0c\x12\x15\n\rnullparameter\x18\x05 \x01(\x08\"<\n\x10SharedPreference\x12\x0c\n\x04\x66ile\x18\x01 \x01(\t\x12\x0b\n\x03key\x18\x02 \x01(\t\x12\r\n\x05value\x18\x03 \x01(\t\"A\n\nAttachment\x12\r\n\x05rowId\x18\x01 \x01(\x04\x12\x14\n\x0c\x61ttachmentId\x18\x02 \x01(\x04\x12\x0e\n\x06length\x18\x03 \x01(\r\"(\n\x07Sticker\x12\r\n\x05rowId\x18\x01 \x01(\x04\x12\x0e\n\x06length\x18\x02 \x01(\r\";\n\x06\x41vatar\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x13\n\x0brecipientId\x18\x03 \x01(\t\x12\x0e\n\x06length\x18\x02 \x01(\r\"\"\n\x0f\x44\x61tabaseVersion\x12\x0f\n\x07version\x18\x01 \x01(\r\"\"\n\x06Header\x12\n\n\x02iv\x18\x01 \x01(\x0c\x12\x0c\n\x04salt\x18\x02 \x01(\x0c\"\xa5\x02\n\x0b\x42\x61\x63kupFrame\x12\x1e\n\x06header\x18\x01 \x01(\x0b\x32\x0e.signal.Header\x12\'\n\tstatement\x18\x02 \x01(\x0b\x32\x14.signal.SqlStatement\x12,\n\npreference\x18\x03 \x01(\x0b\x32\x18.signal.SharedPreference\x12&\n\nattachment\x18\x04 \x01(\x0b\x32\x12.signal.Attachment\x12(\n\x07version\x18\x05 \x01(\x0b\x32\x17.signal.DatabaseVersion\x12\x0b\n\x03\x65nd\x18\x06 \x01(\x08\x12\x1e\n\x06\x61vatar\x18\x07 \x01(\x0b\x32\x0e.signal.Avatar\x12 \n\x07sticker\x18\x08 \x01(\x0b\x32\x0f.signal.StickerB1\n!org.thoughtcrime.securesms.backupB\x0c\x42\x61\x63kupProtos'
)




_SQLSTATEMENT_SQLPARAMETER = _descriptor.Descriptor(
  name='SqlParameter',
  full_name='signal.SqlStatement.SqlParameter',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='stringParamter', full_name='signal.SqlStatement.SqlParameter.stringParamter', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='integerParameter', full_name='signal.SqlStatement.SqlParameter.integerParameter', index=1,
      number=2, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='doubleParameter', full_name='signal.SqlStatement.SqlParameter.doubleParameter', index=2,
      number=3, type=1, cpp_type=5, label=1,
      has_default_value=False, default_value=float(0),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='blobParameter', full_name='signal.SqlStatement.SqlParameter.blobParameter', index=3,
      number=4, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='nullparameter', full_name='signal.SqlStatement.SqlParameter.nullparameter', index=4,
      number=5, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=117,
  serialized_end=252,
)

_SQLSTATEMENT = _descriptor.Descriptor(
  name='SqlStatement',
  full_name='signal.SqlStatement',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='statement', full_name='signal.SqlStatement.statement', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='parameters', full_name='signal.SqlStatement.parameters', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[_SQLSTATEMENT_SQLPARAMETER, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=26,
  serialized_end=252,
)


_SHAREDPREFERENCE = _descriptor.Descriptor(
  name='SharedPreference',
  full_name='signal.SharedPreference',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='file', full_name='signal.SharedPreference.file', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='key', full_name='signal.SharedPreference.key', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='value', full_name='signal.SharedPreference.value', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=254,
  serialized_end=314,
)


_ATTACHMENT = _descriptor.Descriptor(
  name='Attachment',
  full_name='signal.Attachment',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='rowId', full_name='signal.Attachment.rowId', index=0,
      number=1, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='attachmentId', full_name='signal.Attachment.attachmentId', index=1,
      number=2, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='length', full_name='signal.Attachment.length', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=316,
  serialized_end=381,
)


_STICKER = _descriptor.Descriptor(
  name='Sticker',
  full_name='signal.Sticker',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='rowId', full_name='signal.Sticker.rowId', index=0,
      number=1, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='length', full_name='signal.Sticker.length', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=383,
  serialized_end=423,
)


_AVATAR = _descriptor.Descriptor(
  name='Avatar',
  full_name='signal.Avatar',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='name', full_name='signal.Avatar.name', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='recipientId', full_name='signal.Avatar.recipientId', index=1,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='length', full_name='signal.Avatar.length', index=2,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=425,
  serialized_end=484,
)


_DATABASEVERSION = _descriptor.Descriptor(
  name='DatabaseVersion',
  full_name='signal.DatabaseVersion',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='version', full_name='signal.DatabaseVersion.version', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=486,
  serialized_end=520,
)


_HEADER = _descriptor.Descriptor(
  name='Header',
  full_name='signal.Header',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='iv', full_name='signal.Header.iv', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='salt', full_name='signal.Header.salt', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=522,
  serialized_end=556,
)


_BACKUPFRAME = _descriptor.Descriptor(
  name='BackupFrame',
  full_name='signal.BackupFrame',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='header', full_name='signal.BackupFrame.header', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='statement', full_name='signal.BackupFrame.statement', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='preference', full_name='signal.BackupFrame.preference', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='attachment', full_name='signal.BackupFrame.attachment', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='version', full_name='signal.BackupFrame.version', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='end', full_name='signal.BackupFrame.end', index=5,
      number=6, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='avatar', full_name='signal.BackupFrame.avatar', index=6,
      number=7, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='sticker', full_name='signal.BackupFrame.sticker', index=7,
      number=8, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=559,
  serialized_end=852,
)

_SQLSTATEMENT_SQLPARAMETER.containing_type = _SQLSTATEMENT
_SQLSTATEMENT.fields_by_name['parameters'].message_type = _SQLSTATEMENT_SQLPARAMETER
_BACKUPFRAME.fields_by_name['header'].message_type = _HEADER
_BACKUPFRAME.fields_by_name['statement'].message_type = _SQLSTATEMENT
_BACKUPFRAME.fields_by_name['preference'].message_type = _SHAREDPREFERENCE
_BACKUPFRAME.fields_by_name['attachment'].message_type = _ATTACHMENT
_BACKUPFRAME.fields_by_name['version'].message_type = _DATABASEVERSION
_BACKUPFRAME.fields_by_name['avatar'].message_type = _AVATAR
_BACKUPFRAME.fields_by_name['sticker'].message_type = _STICKER
DESCRIPTOR.message_types_by_name['SqlStatement'] = _SQLSTATEMENT
DESCRIPTOR.message_types_by_name['SharedPreference'] = _SHAREDPREFERENCE
DESCRIPTOR.message_types_by_name['Attachment'] = _ATTACHMENT
DESCRIPTOR.message_types_by_name['Sticker'] = _STICKER
DESCRIPTOR.message_types_by_name['Avatar'] = _AVATAR
DESCRIPTOR.message_types_by_name['DatabaseVersion'] = _DATABASEVERSION
DESCRIPTOR.message_types_by_name['Header'] = _HEADER
DESCRIPTOR.message_types_by_name['BackupFrame'] = _BACKUPFRAME
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

SqlStatement = _reflection.GeneratedProtocolMessageType('SqlStatement', (_message.Message,), {

  'SqlParameter' : _reflection.GeneratedProtocolMessageType('SqlParameter', (_message.Message,), {
    'DESCRIPTOR' : _SQLSTATEMENT_SQLPARAMETER,
    '__module__' : 'backups_pb2'
    # @@protoc_insertion_point(class_scope:signal.SqlStatement.SqlParameter)
    })
  ,
  'DESCRIPTOR' : _SQLSTATEMENT,
  '__module__' : 'backups_pb2'
  # @@protoc_insertion_point(class_scope:signal.SqlStatement)
  })
_sym_db.RegisterMessage(SqlStatement)
_sym_db.RegisterMessage(SqlStatement.SqlParameter)

SharedPreference = _reflection.GeneratedProtocolMessageType('SharedPreference', (_message.Message,), {
  'DESCRIPTOR' : _SHAREDPREFERENCE,
  '__module__' : 'backups_pb2'
  # @@protoc_insertion_point(class_scope:signal.SharedPreference)
  })
_sym_db.RegisterMessage(SharedPreference)

Attachment = _reflection.GeneratedProtocolMessageType('Attachment', (_message.Message,), {
  'DESCRIPTOR' : _ATTACHMENT,
  '__module__' : 'backups_pb2'
  # @@protoc_insertion_point(class_scope:signal.Attachment)
  })
_sym_db.RegisterMessage(Attachment)

Sticker = _reflection.GeneratedProtocolMessageType('Sticker', (_message.Message,), {
  'DESCRIPTOR' : _STICKER,
  '__module__' : 'backups_pb2'
  # @@protoc_insertion_point(class_scope:signal.Sticker)
  })
_sym_db.RegisterMessage(Sticker)

Avatar = _reflection.GeneratedProtocolMessageType('Avatar', (_message.Message,), {
  'DESCRIPTOR' : _AVATAR,
  '__module__' : 'backups_pb2'
  # @@protoc_insertion_point(class_scope:signal.Avatar)
  })
_sym_db.RegisterMessage(Avatar)

DatabaseVersion = _reflection.GeneratedProtocolMessageType('DatabaseVersion', (_message.Message,), {
  'DESCRIPTOR' : _DATABASEVERSION,
  '__module__' : 'backups_pb2'
  # @@protoc_insertion_point(class_scope:signal.DatabaseVersion)
  })
_sym_db.RegisterMessage(DatabaseVersion)

Header = _reflection.GeneratedProtocolMessageType('Header', (_message.Message,), {
  'DESCRIPTOR' : _HEADER,
  '__module__' : 'backups_pb2'
  # @@protoc_insertion_point(class_scope:signal.Header)
  })
_sym_db.RegisterMessage(Header)

BackupFrame = _reflection.GeneratedProtocolMessageType('BackupFrame', (_message.Message,), {
  'DESCRIPTOR' : _BACKUPFRAME,
  '__module__' : 'backups_pb2'
  # @@protoc_insertion_point(class_scope:signal.BackupFrame)
  })
_sym_db.RegisterMessage(BackupFrame)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
