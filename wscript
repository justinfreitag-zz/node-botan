import Options

import os
import os.path as path

srcdir = "."
blddir = "build"
VERSION = "0.0.1"

def set_options(opt):
  opt.tool_options("compiler_cxx")
  opt.add_option('--debug', action='store', default=False, help='Enable debugging output')

def configure(conf):
  conf.check_tool("compiler_cxx")
  conf.check_tool("node_addon")
  conf.check(lib='botan-1.10', uselib_store='LIBBOTAN-1.10')

def build(bld):
  obj = bld.new_task_gen("cxx", "shlib", "node_addon")
  obj.cxxflags = ['-g', 
    '-D_FILE_OFFSET_BITS=64',
    '-D_LARGEFILE_SOURCE', 
    '-Wall']
  obj.target = "botan"
  obj.source = "node-botan.cpp"
  obj.uselib = ['LIBBOTAN-1.10']
  if (Options.options.debug != False) and (Options.options.debug == 'true'):
    obj.defines = "ENABLE_DEBUG=1"

def shutdown():
  if Options.commands['clean']:
    if path.exists('node-botan.node'):
      os.unlink('node-botan.node')
    if path.exists('build/default/node-botan.node'):
      os.unlink('build/default/node-botan.node')

    if path.exists('build/default/node-botan.node') and not path.exists('node-botan.node'):
      os.symlink('build/default/node-botan.node', 'node-botan.node')

