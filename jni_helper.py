# -*- coding:utf-8 -*-
__author__ = 'fei_cong'

from idaapi import *
from idautils import *
from idc import *
import sys
import re


def found_method(method, addr):
    #print "[+] Found method '{}' at {}".format(method, hex(addr))
    pass

def get_code_seg():
    seg = FirstSeg()
    while seg != BADADDR:
        '''
        name = SegName(seg)
        if name == '.text':
        '''
        seg_attr = GetSegmentAttr(seg, SEGATTR_TYPE)
        if seg_attr == SEG_CODE:
            return seg
        seg = NextSeg(seg)
    return BADADDR

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
    # or run make_sig.py xxx_dir method_sig.txt
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

def add_jni_struct():
    if BADADDR == GetStrucIdByName("JNINativeInterface"):
        AddStrucEx(-1, "JNINativeInterface", 0)

        id = GetStrucIdByName("JNINativeInterface")
        AddStrucMember(id, "reserved0", 0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "reserved1", 0X4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "reserved2", 0X8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "reserved3", 0XC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetVersion", 0X10, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "DefineClass", 0X14, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "FindClass", 0X18, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "FromReflectedMethod", 0X1C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "FromReflectedField", 0X20, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ToReflectedMethod", 0X24, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetSuperclass", 0X28, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "IsAssignableFrom", 0X2C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ToReflectedField", 0X30, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "Throw", 0X34, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ThrowNew", 0X38, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ExceptionOccurred", 0X3C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ExceptionDescribe", 0X40, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ExceptionClear", 0X44, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "FatalError", 0X48, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "PushLocalFrame", 0X4C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "PopLocalFrame", 0X50, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewGlobalRef", 0X54, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "DeleteGlobalRef", 0X58, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "DeleteLocalRef", 0X5C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "IsSameObject", 0X60, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewLocalRef", 0X64, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "EnsureLocalCapacity", 0X68, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "AllocObject", 0X6C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewObject", 0X70, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewObjectV", 0X74, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewObjectA", 0X78, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetObjectClass", 0X7C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "IsInstanceOf", 0X80, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetMethodID", 0X84, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallObjectMethod", 0X88, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallObjectMethodV", 0X8C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallObjectMethodA", 0X90, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallBooleanMethod", 0X94, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallBooleanMethodV", 0X98, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallBooleanMethodA", 0X9C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallByteMethod", 0XA0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallByteMethodV", 0XA4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallByteMethodA", 0XA8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallCharMethod", 0XAC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallCharMethodV", 0XB0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallCharMethodA", 0XB4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallShortMethod", 0XB8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallShortMethodV", 0XBC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallShortMethodA", 0XC0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallIntMethod", 0XC4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallIntMethodV", 0XC8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallIntMethodA", 0XCC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallLongMethod", 0XD0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallLongMethodV", 0XD4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallLongMethodA", 0XD8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallFloatMethod", 0XDC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallFloatMethodV", 0XE0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallFloatMethodA", 0XE4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallDoubleMethod", 0XE8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallDoubleMethodV", 0XEC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallDoubleMethodA", 0XF0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallVoidMethod", 0XF4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallVoidMethodV", 0XF8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallVoidMethodA", 0XFC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualObjectMethod", 0X100, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualObjectMethodV", 0X104, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualObjectMethodA", 0X108, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualBooleanMethod", 0X10C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualBooleanMethodV", 0X110, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualBooleanMethodA", 0X114, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualByteMethod", 0X118, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualByteMethodV", 0X11C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualByteMethodA", 0X120, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualCharMethod", 0X124, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualCharMethodV", 0X128, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualCharMethodA", 0X12C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualShortMethod", 0X130, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualShortMethodV", 0X134, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualShortMethodA", 0X138, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualIntMethod", 0X13C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualIntMethodV", 0X140, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualIntMethodA", 0X144, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualLongMethod", 0X148, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualLongMethodV", 0X14C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualLongMethodA", 0X150, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualFloatMethod", 0X154, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualFloatMethodV", 0X158, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualFloatMethodA", 0X15C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualDoubleMethod", 0X160, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualDoubleMethodV", 0X164, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualDoubleMethodA", 0X168, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualVoidMethod", 0X16C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualVoidMethodV", 0X170, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallNonvirtualVoidMethodA", 0X174, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetFieldID", 0X178, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetObjectField", 0X17C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetBooleanField", 0X180, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetByteField", 0X184, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetCharField", 0X188, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetShortField", 0X18C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetIntField", 0X190, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetLongField", 0X194, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetFloatField", 0X198, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetDoubleField", 0X19C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetObjectField", 0X1A0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetBooleanField", 0X1A4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetByteField", 0X1A8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetCharField", 0X1AC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetShortField", 0X1B0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetIntField", 0X1B4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetLongField", 0X1B8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetFloatField", 0X1BC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetDoubleField", 0X1C0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStaticMethodID", 0X1C4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticObjectMethod", 0X1C8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticObjectMethodV", 0X1CC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticObjectMethodA", 0X1D0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticBooleanMethod", 0X1D4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticBooleanMethodV", 0X1D8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticBooleanMethodA", 0X1DC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticByteMethod", 0X1E0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticByteMethodV", 0X1E4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticByteMethodA", 0X1E8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticCharMethod", 0X1EC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticCharMethodV", 0X1F0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticCharMethodA", 0X1F4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticShortMethod", 0X1F8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticShortMethodV", 0X1FC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticShortMethodA", 0X200, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticIntMethod", 0X204, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticIntMethodV", 0X208, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticIntMethodA", 0X20C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticLongMethod", 0X210, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticLongMethodV", 0X214, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticLongMethodA", 0X218, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticFloatMethod", 0X21C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticFloatMethodV", 0X220, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticFloatMethodA", 0X224, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticDoubleMethod", 0X228, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticDoubleMethodV", 0X22C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticDoubleMethodA", 0X230, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticVoidMethod", 0X234, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticVoidMethodV", 0X238, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "CallStaticVoidMethodA", 0X23C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStaticFieldID", 0X240, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStaticObjectField", 0X244, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStaticBooleanField", 0X248, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStaticByteField", 0X24C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStaticCharField", 0X250, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStaticShortField", 0X254, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStaticIntField", 0X258, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStaticLongField", 0X25C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStaticFloatField", 0X260, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStaticDoubleField", 0X264, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetStaticObjectField", 0X268, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetStaticBooleanField", 0X26C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetStaticByteField", 0X270, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetStaticCharField", 0X274, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetStaticShortField", 0X278, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetStaticIntField", 0X27C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetStaticLongField", 0X280, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetStaticFloatField", 0X284, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetStaticDoubleField", 0X288, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewString", 0X28C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStringLength", 0X290, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStringChars", 0X294, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ReleaseStringChars", 0X298, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewStringUTF", 0X29C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStringUTFLength", 0X2A0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStringUTFChars", 0X2A4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ReleaseStringUTFChars", 0X2A8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetArrayLength", 0X2AC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewObjectArray", 0X2B0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetObjectArrayElement", 0X2B4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetObjectArrayElement", 0X2B8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewBooleanArray", 0X2BC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewByteArray", 0X2C0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewCharArray", 0X2C4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewShortArray", 0X2C8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewIntArray", 0X2CC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewLongArray", 0X2D0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewFloatArray", 0X2D4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewDoubleArray", 0X2D8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetBooleanArrayElements", 0X2DC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetByteArrayElements", 0X2E0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetCharArrayElements", 0X2E4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetShortArrayElements", 0X2E8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetIntArrayElements", 0X2EC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetLongArrayElements", 0X2F0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetFloatArrayElements", 0X2F4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetDoubleArrayElements", 0X2F8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ReleaseBooleanArrayElements", 0X2FC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ReleaseByteArrayElements", 0X300, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ReleaseCharArrayElements", 0X304, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ReleaseShortArrayElements", 0X308, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ReleaseIntArrayElements", 0X30C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ReleaseLongArrayElements", 0X310, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ReleaseFloatArrayElements", 0X314, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ReleaseDoubleArrayElements", 0X318, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetBooleanArrayRegion", 0X31C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetByteArrayRegion", 0X320, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetCharArrayRegion", 0X324, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetShortArrayRegion", 0X328, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetIntArrayRegion", 0X32C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetLongArrayRegion", 0X330, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetFloatArrayRegion", 0X334, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetDoubleArrayRegion", 0X338, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetBooleanArrayRegion", 0X33C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetByteArrayRegion", 0X340, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetCharArrayRegion", 0X344, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetShortArrayRegion", 0X348, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetIntArrayRegion", 0X34C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetLongArrayRegion", 0X350, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetFloatArrayRegion", 0X354, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "SetDoubleArrayRegion", 0X358, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "RegisterNatives", 0X35C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "UnregisterNatives", 0X360, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "MonitorEnter", 0X364, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "MonitorExit", 0X368, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetJavaVM", 0X36C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStringRegion", 0X370, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStringUTFRegion", 0X374, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetPrimitiveArrayCritical", 0X378, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ReleasePrimitiveArrayCritical", 0X37C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetStringCritical", 0X380, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ReleaseStringCritical", 0X384, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewWeakGlobalRef", 0X388, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "DeleteWeakGlobalRef", 0X38C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "ExceptionCheck", 0X390, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "NewDirectByteBuffer", 0X394, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetDirectBufferAddress", 0X398, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetDirectBufferCapacity", 0X39C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        #SetStrucAlign(id, 2)
        idc.Eval('SetStrucAlign({}, 2);'.format(id))

    if BADADDR == GetStrucIdByName("JNIInvokeInterface"):
        AddStrucEx(-1, "JNIInvokeInterface", 0)
        id = GetStrucIdByName("JNIInvokeInterface")
        AddStrucMember(id, "reserved0", 0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "reserved1", 0X4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "reserved2", 0X8, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "DestroyJavaVM", 0XC, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "AttachCurrentThread", 0X10, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "DetachCurrentThread", 0X14, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "GetEnv", 0X18, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "AttachCurrentThreadAsDaemon", 0X1C, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        #SetStrucAlign(id, 2)
        idc.Eval('SetStrucAlign({}, 2);'.format(id))
        # idaapi.run_statements('auto id; id = GetStrucIdByName("JNIInvokeInterface"); SetStrucAlign(id, 2);')

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
                'com_xxx_fun'
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
    print "=============================================================="
    print "       android jni helper script for reverse engineering.     "
    print "                       Version v1.1                           "
    print "=============================================================="
    add_jni_struct()
    addr = get_code_seg()
    print 'code addr:', hex(addr)
    symbols = []
    for funcea in Functions(SegStart(addr)):
        functionName = GetFunctionName(funcea)
        #print functionName
        symbols.append((functionName, funcea))

    jni_symbols = []
    for s in symbols:
        #print 's0:', s[0]
        if s[0].startswith('Java_'):
            found_method(s[0], s[1])
            jni_symbols.append((s[0], s[1]))

        if 'JNI_OnLoad' in s[0]:
            found_method(s[0], s[1])
            SetType(s[1], 'jint __fastcall JNI_OnLoad(JavaVM* vm, void* reserved)')

    if len(list(jni_symbols)) <= 0:
        print 'no jni symbol found.'
        exit(0)

    print 'select java sig file.'
    '''
    public native int Java_com_xxx_f1();
    public native int Java_com_xxx_f2();
    public native int Java_com_xxx_f3();
    '''
    sig_file = AskFile(0, '*.*', 'open sig file')
    if sig_file:
        print sig_file
        java_sigs = get_java_sigs(sig_file)
        #print java_sigs
        for jni_symbol in jni_symbols:
            jni_name = jni_symbol[0]
            jni_addr = jni_symbol[1]
            #print 'jni_name ', jni_name
            #print 'jni_addr ', jni_addr
            #assert jni_name in java_sigs
            if not jni_name in java_sigs:
                print '%s not found, need fix!!!' % jni_name
            if jni_name in java_sigs:
                java_sig = java_sigs[jni_name]
                if java_sig:
                    jni_sig = get_jni_sig(java_sig)
                    print jni_sig
                    if len(jni_sig) > 0:
                        print 'Setting 0x%X with sig: %s' % (jni_addr, jni_sig)
                        SetType(jni_addr, jni_sig)

