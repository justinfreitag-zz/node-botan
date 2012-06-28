{
  'targets': [
    {
      'target_name': 'botan',
      'sources': [
        'src/node-botan.cpp'
      ],
      'cflags!': [ '-fno-exceptions', '-fno-rtti' ],
      'cflags_cc!': [ '-fno-exceptions', '-fno-rtti' ],
      'cflags': [
        '-g',
        '-D_FILE_OFFSET_BITS=64',
        '-D_LARGEFILE_SOURCE',
        '-Wall',
        '-std=c++0x'
      ],
      'link_settings': {
        'ldflags': [
          '<!@(pkg-config --libs-only-l --libs-only-other botan-1.10)'
        ],
        'libraries': [
          '<!@(pkg-config --libs-only-l botan-1.10)',
        ],
      },
    },
  ]
}

