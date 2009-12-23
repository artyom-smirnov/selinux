#!/usr/bin/python -E


import os
import errno
import shutil
import sys
from optparse import OptionParser

import bz2
import ctypes

sepol = ctypes.cdll.LoadLibrary('libsepol.so')

try:
	import selinux
	import semanage
except:
	print >> sys.stderr, "You must install libselinux-python and libsemanage-python before running this tool"
	exit(1)




# For some reason this function doesn't exist in libselinux :\
def copy_with_context(src, dst):
	if DEBUG:
		print "copying %s to %s" % (src, dst)
	try:
		con = selinux.lgetfilecon_raw(src)[1]
	except:
		print >> sys.stderr, "Could not get file context of %s" % src
		exit(1)

	try:
		selinux.setfscreatecon_raw(con)
	except:
		print >> sys.stderr, "Could not set fs create context: %s" %con
		exit(1)

	try:
		shutil.copy2(src, dst)
	except OSError as (err, strerr):
		print >> sys.stderr, "Could not copy %s to %s, %s" %(src, dst, strerr)

def create_dir_from(src, dst, mode):
	if DEBUG: print "Making directory %s" % dst
	try:
		con = selinux.lgetfilecon_raw(src)[1]
		selinux.setfscreatecon_raw(con)
		os.mkdir(dst, mode)	
	except OSError as (err, stderr):
		if err == errno.EEXIST:
			pass
		else:
			print >> sys.stderr, "Error creating %s" % dst
			exit(1)
	
def copy_module(store, name, con, base):
	if DEBUG: print "Install module %s" % name	
	(file, ext) = os.path.splitext(name)
	if ext != ".pp":
		# Stray non-pp file in modules directory, skip
		print >> sys.stderr, "warning: %s has invalid extension, skipping" % name
		return
	try:
		selinux.setfscreatecon_raw(con)
	
		if base:
			root = oldstore_path(store)
		else:
			root = oldmodules_path(store)

		bottomdir = bottomdir_path(store)
			
		# Special case "base" since you can have modules named base 
		if base:
			file = "_base"

		os.mkdir("%s/%s" % (bottomdir, file))

		copy_with_context(os.path.join(root, name), "%s/%s/%s%s" % (bottomdir, file, file, ext))

		# This is the ext file that will eventually be used to choose a compiler
		efile = open("%s/%s/lang_ext" % (bottomdir, file), "w+", 0600)
		efile.write("pp")
		efile.close()

		# This is the version file that stores the version of the module
		version = "1.0.0"
		if not base:
			try:
				pf = ctypes.c_void_p()
				sepol.sepol_policy_file_create(ctypes.byref(pf))

				pbuffer = None
				try:
					pbuffer = bz2.BZ2File(os.path.join(root, name)).read()
				except:
					pbuffer = open(os.path.join(root, name)).read()

				if (pbuffer == None):
					raise Exception("Unable read policy file into memory.")

				cbuffer = ctypes.create_string_buffer(pbuffer)
				sepol.sepol_policy_file_set_mem(pf, cbuffer, len(cbuffer))

				header_file_type = ctypes.c_int()
				header_name = ctypes.c_char_p()
				header_version = ctypes.c_char_p()

				ret = sepol.sepol_module_package_info(pf, ctypes.byref(header_file_type), ctypes.byref(header_name), ctypes.byref(header_version))
				if (ret != 0):
					raise Exception("Unable to parse package header.")

				version = header_version.value

				sepol.sepol_policy_file_free(pf)

			except Exception as e:
				print >> sys.stderr, e
				print >> sys.stderr, "warning: unable to determine version, using default value"

		efile = open("%s/%s/version" % (bottomdir, file), "w+", 0600)
		efile.write(version)
		efile.close()

	except:
		print >> sys.stderr, "Error installing module %s" % name

def migrate_store(store):

	oldstore = oldstore_path(store);
	oldmodules = oldmodules_path(store);
	newstore = newstore_path(store);
	newmodules = newmodules_path(store);
	bottomdir = bottomdir_path(store);

	print "Migrating from %s to %s" % (oldstore, newstore)

	# Build up new directory structure
	create_dir_from(selinux.selinux_policy_root(), "%s/%s" % (newroot_path(), store), 0755)
	create_dir_from(oldmodules, newstore, 0700)
	create_dir_from(oldstore, newmodules, 0700)
	create_dir_from(oldstore, bottomdir, 0700)

	# use whatever the file context of bottomdir is for the module directories
	con = selinux.lgetfilecon_raw(bottomdir)[1]

	# Special case for base since it was in a different location
	copy_module(store, "base.pp", con, 1)

	# Dir structure built, start copying files
	for root, dirs, files in os.walk(oldstore):
		if root == oldstore:
			# This is the top level directory, need to move 
			for name in files:
				# Check to see if it is in TOPPATHS and copy if so
				if name in TOPPATHS:
					copy_with_context(os.path.join(root, name), os.path.join(newstore, name))

		elif root == oldmodules:
			# This should be the modules directory
			for name in files:
				copy_module(store, name, con, 0)

def rebuild_policy():
	# Ok, the modules are loaded, lets try to rebuild the policy
	print "Attempting to rebuild policy from %s" % newroot_path()

	curstore = selinux.selinux_getpolicytype()[1]

	handle = semanage.semanage_handle_create()
	if not handle:
		print >> sys.stderr, "Could not create semanage handle"
		exit(1)

	semanage.semanage_select_store(handle, curstore, semanage.SEMANAGE_CON_DIRECT)

	if not semanage.semanage_is_managed(handle):
		semanage.semanage_handle_destroy(handle)
		print >> sys.stderr, "SELinux policy is not managed or store cannot be accessed."
		exit(1)

	rc = semanage.semanage_access_check(handle)
	if rc < semanage.SEMANAGE_CAN_WRITE:
		semanage.semanage_handle_destroy(handle)
		print >> sys.stderr, "Cannot write to policy store."
		exit(1)

	rc = semanage.semanage_connect(handle)
	if rc < 0:
		semanage.semanage_handle_destroy(handle)
		print >> sys.stderr, "Could not establish semanage connection"
		exit(1)

	semanage.semanage_set_rebuild(handle, 1)

	rc = semanage.semanage_begin_transaction(handle)
	if rc < 0:
		semanage.semanage_handle_destroy(handle)
		print >> sys.stderr, "Could not begin transaction"
		exit(1)

	rc = semanage.semanage_commit(handle)
	if rc < 0:
		print >> sys.stderr, "Could not commit transaction"

	semanage.semanage_handle_destroy(handle)


def oldroot_path():
	return "/etc/selinux"

def oldstore_path(store):
	return "%s/%s/modules/active" % (oldroot_path(), store)

def oldmodules_path(store):
	return "%s/modules" % oldstore_path(store)

def newroot_path():
	return "/var/lib/selinux"

def newstore_path(store):
	return "%s/%s/active" % (newroot_path(), store)

def newmodules_path(store):
	return "%s/modules" % newstore_path(store)

def bottomdir_path(store):
	return "%s/%s" % (newmodules_path(store), PRIORITY)


if __name__ == "__main__":

	parser = OptionParser()
	parser.add_option("-p", "--priority", dest="priority", default="100",
			  help="Set priority of modules in new store (default: 100)")
	parser.add_option("-s", "--store", dest="store", default=None,
			  help="Store to read from and write to")
	parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False,
			  help="Output debug information")
	parser.add_option("-c", "--clean", dest="clean", action="store_true", default=False,
			  help="Clean old modules directory after migrate (default: no)")

	(options, args) = parser.parse_args()

	DEBUG = options.debug
	PRIORITY = options.priority
	TYPE = options.store
	CLEAN = options.clean

	# List of paths that go in the active 'root'
	TOPPATHS = [
		"file_contexts",
		"homedir_template",
		"file_contexts.template",
		"commit_num",
		"ports.local",
		"interfaces.local",
		"nodes.local",
		"booleans.local",
		"file_contexts.local",
		"seusers",
		"users.local",
		"users_extra.local",
		"seusers.final",
		"users_extra",
		"netfilter_contexts",
		"file_contexts.homedirs",
		"disable_dontaudit" ]


	create_dir_from(oldroot_path(), newroot_path(), 0755)

	stores = None
	if TYPE is not None:
		stores = [TYPE]
	else:
		stores = os.listdir(oldroot_path())

	# find stores in oldroot and migrate them to newroot if necessary
	for store in stores:
		if not os.path.isdir(oldmodules_path(store)):
			# already migrated or not an selinux store
			continue

		if os.path.isdir(newstore_path(store)):
			# store has already been migrated, but old modules dir still exits
			print >> sys.stderr, "warning: Policy type %s has already been migrated, but modules still exist in the old store. Skipping store." % store
			continue

		migrate_store(store)

		if CLEAN is True:
			def remove_error(function, path, execinfo):
				print >> sys.stderr, "warning: Unable to remove old store modules directory %s. Cleaning failed." % oldmodules_path(store)
			shutil.rmtree(oldmodules_path(store), onerror=remove_error)

	rebuild_policy()

