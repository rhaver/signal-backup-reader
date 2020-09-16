"""
https://github.com/rhaver/signal-backup-reader

This script is meant to read backup files created by the messaging app Signal
(https://signal.org/).
"""

import io
import os
import argparse
from pathlib import Path
import logging
import sqlite3
import mimetypes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import ciphers
import backups_pb2 as protobuffed

class ByteHelper:
	"""A class with helper functions for processing integers on byte level."""
	BYTE_ORDER = 'big'
	INT_SIGNED = False

	@classmethod
	def read_bytes_int(cls, bytes, byteorder=None, signed=None):
		"""Convert (multiple) bytes to an integer."""
		#
		# set default options
		byteorder = byteorder if byteorder is not None else cls.BYTE_ORDER
		signed = signed if signed is not None else cls.INT_SIGNED
		# get int
		return int.from_bytes(bytes, byteorder=byteorder, signed=signed)

	@classmethod
	def write_bytes_int(cls, i, length=4, byteorder=None, signed=None):
		"""Convert an integer to a byte encoding."""
		#
		# set default options
		byteorder = byteorder if byteorder is not None else cls.BYTE_ORDER
		signed = signed if signed is not None else cls.INT_SIGNED
		# get bytes
		return int.to_bytes(i, length=length, byteorder=byteorder, signed=signed)

	@staticmethod
	def unsigned_to_signed(u, bits=8):
		"""Convert an unsigned integer value to a signed one."""
		cutoff = (1<<(bits - 1))
		return (u - (cutoff<<1)) if (u & cutoff) else u

	@staticmethod
	def unsigned_to_signed_64bits(u):
		"""Convert an unsigned 64-bit integer value to a signed one."""
		return (u - 0x10000000000000000) if (u & 0x8000000000000000) else u


class SignalBackupReader:
	"""Class for reading a Signal backup file."""
	
	@staticmethod
	def _read_frame(bytestream):
		"""Read in a raw undecrypted frame from the bytestream."""
		size = ByteHelper.read_bytes_int(bytestream.read(4))
		return bytestream.read(size)

	@staticmethod
	def _parse_frame(rawbytes):
		"""Unmarshall a frame from its decrypted raw byte form."""
		return protobuffed.BackupFrame.FromString(rawbytes)

	@staticmethod
	def _print_progress(percent, done=False):
		"""Print percentage of progress throught the backup file."""
		print('Processing file: {:6.2f}%'.format(percent), end='\r')
		if done:
			print('\nDone. See log file for details.')

	def __init__(self, filename, password, output_folder, write_attachments=False, write_sqlite_db=False):
		"""Process a Signal backup file. Process all frames and extract the
		information in them, either to an SQL file and optionally an SQLite
		database (statement frames), files (attachment/sticker/avatar frames),
		or to the log file (preference frames).
		"""
		
		# resolve output path
		self._output_path = Path(output_folder).resolve()
		self._output_path.mkdir(parents=True, exist_ok=True)
		# configure logging
		self.logger = logging.getLogger()
		self.logger.propagate = False
		self.logger.setLevel(logging.DEBUG)
		handler = logging.FileHandler(self._output_path / 'read-signal-backup.log', mode='w', encoding='utf-8')
		handler.setFormatter(logging.Formatter('%(asctime)s >> %(message)s'))
		self.logger.addHandler(handler)
		self.logger.info('Processing file "%s" to output folder "%s"', filename, self._output_path)
		
		# resolve output path for attachments (if their output is requested)
		if write_attachments:
			self._attachment_path = (self._output_path / 'attachments').resolve()
			self._attachment_path.mkdir(exist_ok=True)
			# set up infrastructure for gathering mimetypes
			self._mimetypes = {}
			for mime, ext in [
				('text/x-signal-plain', '.txt'),
				('audio/flac', '.flac'),
				('audio/mp4', '.mp4'),
				('application/epub+zip', '.epub'),
				('video/x-matroska', '.mkv'),
				('image/webp', '.webp'),
				('video/mp2ts', 'm2ts')]:
				mimetypes.add_type(mime, ext, strict=False)
		else:
			self._attachment_path = None
		password = password.replace(' ', '').strip()
		
		# set up SQLite connection (if output to a SQLite db is requested)
		if write_sqlite_db:
			p = (self._output_path / 'sqlite.db').resolve()
			if p.exists():
				p.unlink()
			self._sqlite_connection = sqlite3.connect(p)
		else:
			self._sqlite_connection = None
		
		# for statistics, set up a histogram/counter
		histo = {key: 0 for key in ['header', 'statement', 'preference', 'attachment', 'version', 'end', 'avatar', 'sticker']}

		# commence the file processing
		try:
			filesize = os.path.getsize(filename)
			with io.open(filename, 'rb', buffering=1024) as f_in, \
				io.open(self._output_path / 'log-statements.sql', 'w', encoding='utf-8') as self._log_statements:

				self._print_progress(0.)
				
				# the first frame (the header frame) is unencrypted
				currentframe, f = self._parse_frame(self._read_frame(f_in)), 1
				
				# process subsequent frames until the end frame is encountered
				while (not currentframe.end):
					# update histogram of frame type		
					for key in histo:
						if currentframe.HasField(key):
							histo[key] += 1

					# process frame
					if currentframe.HasField('header'):
						self._process_header(currentframe.header, password)
					elif currentframe.HasField('version'):
						self._process_version(currentframe.version)
					elif currentframe.HasField('statement'):
						self._process_statement(currentframe.statement)
					elif currentframe.HasField('preference'):
						self._process_preference(currentframe.preference)
					elif currentframe.HasField('attachment'):
						self._process_attachment(currentframe.attachment, f_in)
					elif currentframe.HasField('sticker'):
						self._process_sticker(currentframe.sticker, f_in)
					elif currentframe.HasField('avatar'):
						self._process_avatar(currentframe.avatar, f_in)
					else:
						self.logger.error('Cannot process unknown type of frame %s: %s', f, currentframe)
					
					# log progress periodically
					if f % 10 == 0:
						self._print_progress(100 * f_in.tell() / filesize)
						if f % 1000 == 0:
							self.logger.info(f'Processed frame %s.', f)
							# commit pending changes to the sqlite db
							if self._sqlite_connection is not None:
								self._sqlite_connection.commit()

					# load next frame
					currentframe, f = self._read_decrypt_and_parse_frame(f_in), f + 1
				
				# end frame encountered, we are done
				histo['end'] += 1
				self.logger.info('Total frames: %s', f)
				self.logger.info('Frame types and their frequency: %s', histo)
				self.logger.info('Encountered end frame, file pointer position %s (filesize %s)', f_in.tell(), filesize)
		finally:
			# close SQLite connection properly, if there was one
			if self._sqlite_connection is not None:
				# perform final commit and close
				with self._sqlite_connection as conn:
					conn.commit()
			self.logger.removeHandler(handler)
		
		self._print_progress(100, done=True)
	
	def _log_frame(self, type, frame):
		"""Log a frame with its contents."""
		self.logger.info('Encountered %s frame: { %s }', type, str(frame).strip().replace('\n', ', '))
	
	def _decrypt_block(self, block, mac_needs_iv=False):
		"""Decrypt a block of data, with its MAC at the end."""
		# the last ten bytes of the block is the message authentication code
		payload, their_mac = block[:-10], block[-10:]

		# update the iv with the counter
		self._iv_drip[:4] = ByteHelper.write_bytes_int(self._iv_counter)
		self._iv_counter += 1

		# compute mac from the block body and compare
		mac = hmac.HMAC(self._mac_key, hashes.SHA256())
		if mac_needs_iv:
			mac.update(self._iv_drip)
		mac.update(payload)
		our_mac = mac.finalize()[:10]
		if their_mac != our_mac:
			self.logger.debug('MAC fail, their_mac %s our_mac %s', their_mac, our_mac)
			raise Exception('Message Authentication Code fail')
		
		# decrypt contents
		decryptor = ciphers.Cipher(
			ciphers.algorithms.AES(self._cipher_key),
			ciphers.modes.CTR(self._iv_drip)
			).decryptor()
		return decryptor.update(payload) + decryptor.finalize()

	def _read_decrypt_and_parse_frame(self, filestream):
		"""Read in the next frame from the filestream, and decrypt and unmarshall it."""
		return self._parse_frame(self._decrypt_block(self._read_frame(filestream)))
	
	def _process_header(self, header, password):
		"""Process header frame."""
		self._log_frame('header', header)
		# derive encryption key by repeatedly hashing the salted password with SHA512
		digest = hashes.Hash(hashes.SHA512())
		input = password.encode()
		hash = input
		if header.salt:
			digest.update(header.salt)
		for i in range(250000):
			digest.update(hash)
			digest.update(input)
			hash = digest.finalize()
			digest = hashes.Hash(hashes.SHA512())
		key = hash[:32]
		
		# derive secrets
		sha = hashes.SHA256()
		derived = HKDF(sha, 64, bytes(sha.digest_size), 'Backup Export'.encode()).derive(key)
		self._cipher_key, self._mac_key = derived[:32], derived[32:]
		
		# initialize initial vector (nonce) for decryption
		self._iv_drip = bytearray(header.iv)
		self._iv_counter = ByteHelper.read_bytes_int(self._iv_drip[:4])
	
	def _process_version(self, version):
		"""Process version frame."""
		self._log_frame('version', version)
		self._log_statements.write('/* Signal backup version: {} */\n'.format(version.version))
	
	@staticmethod
	def _sql_parameter_to_string(par, idx):
		"""Convert an SqlParameter to a string for insertion into an SQLite statement."""
		prependstring = '/*{0}:{1}*/'
		if par.HasField('stringParamter'):
			# replace newlines so that the SQL statement with this par will be on one line
			return prependstring.format(idx, 'str') + "'" + par.stringParamter.replace("'","''").replace('\n', "'||char(10)||'") + "'"
		elif par.HasField('integerParameter'):
			# convert the unsigned long integer to a signed one
			return prependstring.format(idx, 'int') + str(ByteHelper.unsigned_to_signed_64bits(par.integerParameter))
		elif par.HasField('doubleParameter'):
			return prependstring.format(idx, 'double') + str(par.doubleParameter)
		elif par.HasField('blobParameter'):
			return prependstring.format(idx, 'blob') + "x'" + par.blobParameter.hex() + "'"
		elif par.HasField('nullparameter'):
			return prependstring.format(idx, '') + 'NULL'
		else:
			self.logger.error('Unknown type of SqlParameter to serialize to str: %s', par)
	
	@staticmethod
	def _sql_parameter_to_object(par):
		"""Prepare an SqlParameter for use in a parametrized SQLite statement execution."""
		if par.HasField('stringParamter'):
			return par.stringParamter
		elif par.HasField('integerParameter'):
			# convert the unsigned long integer to a signed one
			return ByteHelper.unsigned_to_signed_64bits(par.integerParameter)
		elif par.HasField('doubleParameter'):
			return par.doubleParameter
		elif par.HasField('blobParameter'):
			return par.blobParameter
		elif par.HasField('nullparameter'):
			return None
		else:
			self.logger.error('Unknown type of SqlParameter to extract as object: %s', par)
	
	def _guess_media_extension(self, type, id):
		"""Guess the file extension for a file based on its mimetype."""
		# could potentially also guess extension based on the binary data with the magic module
		if type == 'sticker':
			return 'webp'
		elif type == 'attachment':
			key = '{0}-{1}'.format(type, id)
			guess = None
			mimetype = self._mimetypes[key] if key in self._mimetypes else None
			if mimetype is not None:
				guess = mimetypes.guess_extension(mimetype, strict=False)
				if guess is not None:
					guess = guess[1:].lower()
				else:
					self.logger.info('mimetype %s not resolved', mimetype)
			return guess or 'bin'
		else:
			return 'bin'
	
	def _record_mimetype(self, type, id, mimetype):
		"""Store the mimetype for an attachment that we encountered in an SQL
		statement, since Signal backup files seem to be consistently structured
		so that all SQL statement frames come before a attachment frame.
		"""
		key = '{0}-{1}'.format(type, id)
		self._mimetypes[key] = mimetype
	
	def _process_statement(self, statement):
		"""Process statement frame."""
		sttmnt = statement.statement
		
		# ignore SQLite's own tables (whose names begins with 'sqlite_')
		# https://github.com/signalapp/Signal-Android/commit/128da6db04d204dee437012d41dec06be4717537
		if sttmnt[:20].lower() != 'create table sqlite_':
			# log the SQL statement (with parameters
			sttmnt_to_log = sttmnt.replace('\r', '').replace('\n', ' ') # make it go on one line
			sttmnt_to_log = sttmnt_to_log.replace('?', '{}').format(*[self._sql_parameter_to_string(par, idx) for idx, par in enumerate(statement.parameters, 1)])
			self._log_statements.write(sttmnt_to_log + '\n')

			# execute SQL statement to the SQLite db we are building (if any)
			pars = None
			if self._sqlite_connection is not None:
				pars = [self._sql_parameter_to_object(par) for par in statement.parameters]
				self._sqlite_connection.execute(sttmnt, pars)

			# record mime types for attachments
			if self._attachment_path is not None:
				# attachments
				if sttmnt[:16].lower() == 'insert into part' and len(statement.parameters) > 19:
					pars19 = self._sql_parameter_to_object(statement.parameters[19]) if pars is None else pars[19]
					pars3 = self._sql_parameter_to_object(statement.parameters[3]) if pars is None else pars[3]
					self._record_mimetype('attachment', pars19, pars3)
				# stickers/avatars
				pass # no mimetype info is recorded for stickers/avatars
	
	def _process_preference(self, preference):
		"""Process preference frame."""
		self._log_frame('preference', preference)

	def _process_attachment(self, attachment, filestream):
		"""Process attachment frame."""
		self._log_frame('attachment', attachment)
		
		# read and decrypt the file's content
		b = filestream.read(attachment.length + 10) # mac is appended
		decrypted = self._decrypt_block(b, mac_needs_iv=True)
		
		# write to file, if requested
		if self._attachment_path is not None:
			filename = self._attachment_path / 'attachment-{0}-{1}.{2}'.format(attachment.rowId, attachment.attachmentId, self._guess_media_extension('attachment', attachment.attachmentId))
			with io.open(filename, 'wb') as f:
				f.write(decrypted)

	def _process_sticker(self, sticker, filestream):
		"""Process sticker frame."""
		self._log_frame('sticker', sticker)
		
		# read and decrypt the file's content
		b = filestream.read(sticker.length + 10) # mac is appended
		decrypted = self._decrypt_block(b, mac_needs_iv=True)
		
		# write to file, if requested
		if self._attachment_path is not None:
			with io.open(self._attachment_path / 'sticker-{0}.bin'.format(sticker.rowId), 'wb') as f:
				f.write(decrypted)

	def _process_avatar(self, avatar, filestream):
		"""Process avatar frame."""
		self._log_frame('avatar', avatar)
		
		# read and decrypt the file's content
		b = filestream.read(avatar.length + 10) # mac is appended
		decrypted = self._decrypt_block(b, mac_needs_iv=True)
		
		# write to file, if requested
		if self._attachment_path is not None:
			with io.open(self._attachment_path / 'avatar-{0}-{1}.bin'.format(avatar.recipientId, avatar.name), 'wb') as f:
				f.write(decrypted)

def main():
	"""Main method for when file is run in script mode."""
	# process command line arguments
	parser = argparse.ArgumentParser(description='Read and extract data from a Signal backup file.')
	parser.add_argument('BackupFile', help='Signal backup file.')
	parser.add_argument('Password', help='Password.')
	parser.add_argument('OutputFolder', help='Output folder.')
	parser.add_argument('--no-attachments', action='store_true', help='Disable the extraction of attachments.')
	parser.add_argument('--no-sqlite', action='store_true', help='Disable executing the SQL commands on an SQLite database.')
	args = parser.parse_args()

	# process the Signal backup file
	SignalBackupReader(
		args.BackupFile,
		args.Password,
		args.OutputFolder,
		write_attachments=not args.no_attachments,
		write_sqlite_db=not args.no_sqlite)

	logging.shutdown()

if __name__ == '__main__':
	main()
