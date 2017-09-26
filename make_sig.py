
import sys
import re
import struct
from binascii import hexlify
import subprocess

import os
import os.path


jni_types = {
        'boolean'  : 'jboolean',
        'byte' : 'jbyte',
        'char' : 'jchar',
        'short'  : 'jshort',
        'int'  : 'jint',
        'long'  : 'jlong',
        'float' : 'jfloat',
        'double'  : 'jdouble',
        'string'  : 'jstring',
        'object' : 'jobject',
        'void' : 'void'
}

def get_jnitype(java_type):
    postfix = ''
    jtype = java_type.lower()
    if jtype.endswith('[]'):
        postfix = 'Array'
        jtype = jtype[:-2]
    tp = ''
    if jtype not in jni_types:
        tp = 'jobject'
    else:
        tp = jni_types[jtype] + postfix

    return tp

def get_args_type(java_args):
    if len(java_args) == 0:
        return 'JNIEnv* env, jobject thiz'
    jargs = java_args.lower()
    args = jargs.split(', ')
    #print 'arg count:', len(args)
    full_arg = 'JNIEnv* env, jobject thiz, '
    i = 1
    for java_arg in args:
        java_type = java_arg.split(' ')[0]
        full_arg += get_jnitype(java_type)
        full_arg += ' arg'
        full_arg += str(i)
        full_arg += ', '
        i += 1

    return full_arg[:-2]

def test_jnitype():
    print get_jnitype('int')
    print get_jnitype('Int')
    print get_jnitype('long')
    print get_jnitype('Long')
    print get_jnitype('void')
    print get_jnitype('String')
    print get_jnitype('String[]')
    print get_jnitype('boolean')
    print get_jnitype('ArrayList<String>')
    print get_jnitype('Object[]')
    print get_jnitype('byte[]')
    print get_jnitype('FileEntry')

def test_args_type():
    print get_args_type('long paramLong1, long paramLong2, String[] paramArrayOfString')
    print get_args_type('String paramString')
    print get_args_type('long paramLong1, long paramLong2, String[] paramArrayOfString')
    print get_args_type('')
    print get_args_type('String paramString, byte[] paramArrayOfByte1, SQLiteCipherSpec paramSQLiteCipherSpec, byte[] paramArrayOfByte2')
    print get_args_type('String paramString, byte[] paramArrayOfByte1, String[] paramArrayOfString, byte[] paramArrayOfByte2')
    print get_args_type('int paramInt, LogCallback paramLogCallback')
    print get_args_type('boolean paramBoolean')
    print get_args_type('long paramLong1, long paramLong2, int paramInt, byte[] paramArrayOfByte')

def get_jni_sig(java_sig):
    # grep -Eo '^( |public|private|protected).* native .*;' -r ./java_dir/ -h > ~/Desktop/method_sig.txt
    # or
    # grep ' native ' -r ./java_dir/ -h > ~/Desktop/method_sig.txt
    '''
    >>> l = "  public static native long nativeLoadMaster(String paramString, byte[] paramArrayOfByte1, String[] paramArrayOfString, byte[] paramArrayOfByte2);"
    >>> rr = re.match('^( |public|private|protected).* native (.*) (.*)[(](.*)[)];', l)
    >>> print "{}".format(rr.group(0))
      public static native long nativeLoadMaster(String paramString, byte[] paramArrayOfByte1, String[] paramArrayOfString, byte[] paramArrayOfByte2);
    >>> print "{}".format(rr.group(1))

    >>> print "{}".format(rr.group(2))
    long
    >>> print "{}".format(rr.group(3))
    nativeLoadMaster
    >>> print "{}".format(rr.group(4))
    String paramString, byte[] paramArrayOfByte1, String[] paramArrayOfString, byte[] paramArrayOfByte2
    '''
    l = java_sig
    rr = re.match('^( |public|private|protected).* native (.*) (.*)[(](.*)[)];', l)
    if not rr:
        return ''
    ret_type = "{}".format(rr.group(2))
    func_name = "{}".format(rr.group(3))
    java_args = "{}".format(rr.group(4))
    jni_sig = get_jnitype(ret_type) + ' __fastcall ' + func_name + '('
    jni_sig += get_args_type(java_args)
    jni_sig += ');'

    return jni_sig

def test_jni_sig():
    print get_jni_sig(' public static native long nativeLoadMaster(String paramString, byte[] paramArrayOfByte1, String[] paramArrayOfString, byte[] paramArrayOfByte2);')
    print get_jni_sig(' private static native long nativeExecuteForCursorWindow(long paramLong1, long paramLong2, long paramLong3, int paramInt1, int paramInt2, boolean paramBoolean);')
    print get_jni_sig(' ')
    print get_jni_sig('private static native int nativeCount(long paramLong);')
    print get_jni_sig('public static native int w(String paramString1, String paramString2);')
    print get_jni_sig('public static native void release();')
    print get_jni_sig('public static native byte[] aesEncrypt(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2);')

def make_sig_file(java_src_dir, sig_file):
    f = file(sig_file, 'w+')
    for parent, dirnames, filenames in os.walk(java_src_dir):
        for filename in filenames:
            #print "file: " + os.path.join(parent, filename)
            filepath = os.path.join(parent, filename)
            with open(filepath) as o:
                content = o.read()
                for m in re.finditer('( |public|private|protected).* native (.*) (.*)[(](.*)[)];', content):
                    rr = re.match('package (.*?);.*?class ([^\s]+)', content, re.S)
                    pkg_name = rr.group(1)
                    class_name = rr.group(2)
                    func_name = m.group(3)
                    print 'func_name:', func_name
                    print 'pkg_name:', pkg_name
                    print 'class_name:', class_name
                    full_func_name = 'Java_' + pkg_name + '_' + class_name + '_' + func_name
                    full_func_name = full_func_name.replace('.', '_')
                    #print 'full_func_name:', full_func_name
                    full_method_sig = m.group(0)
                    full_method_sig = full_method_sig.replace(func_name, full_func_name).strip()
                    #print full_method_sig
                    f.write(full_method_sig + '\n')
    f.close()

def get_java_sigs(sig_file):
    java_sigs = {}
    if sig_file:
        with open(sig_file) as o:
            while True:
                line = o.readline()
                if len(line) == 0:
                    break
                '''
                >>> m = re.match('( |public|private|protected).* native (.*) (.*)[(](.*)[)];', line)
                >>> m.group(3)
                'com_xxx_yyy'
                '''
                m = re.match('( |public|private|protected).* native (.*) (.*)[(](.*)[)];', line)
                if m:
                    method_name = m.group(3)
                    java_sigs[method_name] = m.group(0)
    '''
    for java_sig in java_sigs:
        print java_sig
    '''
    return java_sigs

if __name__ == '__main__':
    test_jnitype()
    #test_args_type()
    test_jni_sig()

    #java_src_dir = "/Users/rmbp/crack/app/android/apktool_outdir"
    #sig_file = '/Users/rmbp/crack/app/android/method_sig.txt'
    java_src_dir = sys.argv[1]
    sig_file = sys.argv[2]
    print(java_src_dir)
    print(java_src_dir)
    make_sig_file(java_src_dir, sig_file)
    java_sigs = get_java_sigs(sig_file)
    print(java_sigs)
