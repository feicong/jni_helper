# Android SO自动化逆向探究

长期从事Android SO动态库分析时，时常会做一些重复性较高的工作。例如，SO库中的`Java_com_xxx_yyy()`等一系统与Java层桥接的方法，逆向它们时，通常需要做如下工作：

1. IDA Pro载入SO，完成第一次的反编译。
2. 导入jni.h头文件，引入`JNINativeInterface`与`JNIInvokeInterface`结构体信息。
3. 设置`Java_com_xxx_yyy()`类型方法的前两个参数为JNIEnv* env与jobject thiz。
4. 如果有F5插件，则进行一次Force call type。
5. ......。

将这些工作自动化，可以大大的提高逆向分析的工作效率。基于IDA Pro提供的脚本与插件系统，可以很方便的完成以上前3项工作。下面，我们一步步来打造一个SO自动化逆向分析的工具。

## 目标细化

在开始完成一个工具前，需要将这些需要解决的问题进行一次量化分析。

首先，如何定位需要处理的SO库方法？由于`Java_com_xxx_yyy()`类型方法与Java层进行桥接，在java层代码中必定会有它的声明。所有的这些方法在Java代码中会有一个`native`属性，只需要遍历Java层的代码，获取所有的`native`方法即可。

其次，不同的方法有不同的参数类型，签名的不同，该如何处理？为了让工具实现起来过于复杂，我们只处理Java中内置的数据类型，自定义的数据类型统一使用`jobject`进行处理与表示。

最后，就是奖获取到的Java层的所有`native`方法信息与IDA Pro中的相应的方法进行一一的对应，并进行方法的自动化类型处理，这就需要用到IDA Pro的脚本功能。

## 功能实现

明确了以上的3个步骤后，下面来动手一一的完成它。

### 解析`native`方法

为了快速的解析`native`方法，我最先想到的是使用`grep`命令（系统为macOS）。首先，使用JD-GUI反编译APK，导出所有的Java源文件，然后在命令行下执行：
```
$ grep ' native ' -r ./java_dir -h
  public native String stringFromJNI();
```

或者执行如下命令：
```
$ grep -Eo '^( |public|private|protected).* native .*;' -r ./java_dir -h
  public native String stringFromJNI();
```

不错，都能够正确获取到`native`方法，虽然输出的前面会有一个JD-GUI反编译带的空格。

为了让Windows的用户，即使在不安装`Mingw`或其他的Linux模拟环境的情况下，也能够正确的获取到方法，我还是决定使用Python来写一个生成方法签名信息的脚本。就即名叫make_sig.py好了。

Python的便捷，让我可以很方法的在命令行下测试re模块的正则表达式，如下：

```
$ python
Python 2.7.10 (default, Feb  7 2017, 00:08:15)
[GCC 4.2.1 Compatible Apple LLVM 8.0.0 (clang-800.0.34)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> import re
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
```

OK，正则表达式弄对了！可以正确的解析一条`native`方法的所有信息：返回值、方法名、签名。我这里不打算展开如何编写正则表达式，因为我觉得很多人应该会了，如果你对于正则表达式不太熟，建议你到这个链接快速的学习一下：`https://github.com/zeeshanu/learn-regex`。

下面的代码片断是解析一个目录下所有的文件，找到`native`方法并保存到指定的文件中：
```
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
```

这段代码不需要太多的解释，`os.walk`会遍历一个目录中所有文件信息，对于目录中的第一个文件，使用`open`打开后，调用`re.finditer`来匹配`native`方法，打到就把它写入到`sig_file`指定的文件名中。

更多的代码参看make_sig.py的文件内容，对于很多人，你只需要知道执行```make_sig.py xxx_out method_sig.txt```就可以生成method_sig.txt方法签名文件了。`xxx_out`为JD-GUI导出的APK的Java源码目录。

### Java数据类型处理
好了，到现在已经取到了所有的`native`方法信息，现在需要对这些方法的签名进行处理。

所有的`native`方法支持的数据类型在jni.h头文件中都有定义，该文件可以在Android NDK任意系统版本的include目录下找到。在文件的开头就有这么一段：
```
typedef uint8_t  jboolean; /* unsigned 8 bits */
typedef int8_t   jbyte;    /* signed 8 bits */
typedef uint16_t jchar;    /* unsigned 16 bits */
typedef int16_t  jshort;   /* signed 16 bits */
typedef int32_t  jint;     /* signed 32 bits */
typedef int64_t  jlong;    /* signed 64 bits */
typedef float    jfloat;   /* 32-bit IEEE 754 */
typedef double   jdouble;  /* 64-bit IEEE 754 */
```

既然最后的处理代码使用Python来写，咱也不含糊，先弄一个`jni_types`如下：
```
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
```

然后，写一个Java层方法类型转换成JNI类型的方法，代码如下：
```
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
```

小小的测试一下：
```
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
```

输出如下：
```
jint
jint
jlong
jlong
void
jstring
jstringArray
jboolean
jobject
jobjectArray
jbyteArray
jobject
```

稳！单个方法的签名解析没问题了，那将整个方法的类型转化为JNI接受的类型也没多大问题，代码如下：
```
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
```

最后是编写`get_jni_sig`方法，实现一个Java的`native`方法签名转成IDA Pro能接受的签名信息。具体看代码，这里就不占篇幅了。

### 自动化设置方法信息
前两步没问题，到这里问题就不大了。下面是写IDAPython代码，来完成一个jni_helper.py脚本工具。

首先是IDA Pro分析SO时候，并不会自动的导入`JNINativeInterface`与`JNIInvokeInterface`结构体信息。这就需要自己来完成了。

`JNINativeInterface`的方法字段忒多，我不打算自己手写，容易出错还效率低下。我使用IDA Pro的导出功能，点击菜单File->Produce File->DUMP typeinfo to IDC file...，然后一个idc文件，然后复制IDC中的内容，简单修改就完成了`add_jni_struct()`方法，代码如下：
```
def add_jni_struct():
    if BADADDR == GetStrucIdByName("JNINativeInterface"):
        AddStrucEx(-1, "JNINativeInterface", 0)

        id = GetStrucIdByName("JNINativeInterface")
        AddStrucMember(id, "reserved0", 0, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        AddStrucMember(id, "reserved1", 0X4, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)
        ......
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
```

比较有趣的是，在IDC中有这么一句：
```
SetStrucAlign(id, 2)
```

这个`SetStrucAlign()`方法在IDAPython中并没有，要想调用它，可以使用如下方法：
```
idc.Eval('SetStrucAlign({}, 2);'.format(id))
```

导入完成后，下一步的工作是获取SO中所有的`Java_com_xxx_yyy()`类型的方法信息，这个好办，代码如下：
```
addr = get_code_seg()
symbols = []
for funcea in Functions(SegStart(addr)):
    functionName = GetFunctionName(funcea)
    symbols.append((functionName, funcea))
```

`symbols`现在存放了所有的方法，只需要判断是否以“Java_”就能区分`native`方法了。

接着是读取前面生成的方法签名文件，读取它的所有方法签名信息，这里我使用如下方法：
```
sig_file = AskFile(0, '*.*', 'open sig file')
```

`AskFile()`方法会弹出一个文件选择框来让用户选择生成的文件，我觉得这种交互比直接写死文件路径要优雅，虽然这里会让你参与进来，可能会使你烦燥。

我们传入获取到的第一条Java方法签名给上一步的`get_jni_sig()`方法，来生成对应的JNI方法签名。最后，调用`SetType()`来设置它的方法签名信息。

至此，所有的工作都完成了。完整的工程见：`https://github.com/feicong/jni_helper`。
