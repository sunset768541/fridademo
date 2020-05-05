function trace(pattern) {
    var type = (pattern.toString().indexOf("!") === -1) ? "java" : "module";

    if (type === "module") {

        // trace Module
        var res = new ApiResolver("module");
        var matches = res.enumerateMatchesSync(pattern);
        var targets = uniqBy(matches, JSON.stringify);
        targets.forEach(function (target) {
            traceModule(target.address, target.name);
        });

    } else if (type === "java") {

        // trace Java Class
        var found = false;
        Java.enumerateLoadedClasses({
            onMatch: function (aClass) {
                if (aClass.match(pattern)) {
                    found = true;
                    var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
                    traceClass(className);
                }
            },
            onComplete: function () {
            }
        });

        // trace Java Method
        if (!found) {
            try {
                traceMethod(pattern);
            } catch (err) { // catch non existing classes/methods
                console.error(err);
            }
        }
    }
}

/*
 function enumMethods(targetClass, targetMethod) {
 //目标类
     var hook = Java.use(targetClass);
 //重载次数
     var overloadCount = hook[targetMethod].overloads.length;
 //打印日志：追踪的方法有多少个重载
     console.log("Tracing " + targetMethod + " [" + overloadCount + " overload(s)]");
 //每个重载都进入一次
     for (var i = 0; i < overloadCount; i++) {
 //hook每一个重载
         hook[targetMethod].overloads[i].implementation = function () {
             console.warn("n*** entered " + targetMethod);

             //可以打印每个重载的调用栈，对调试有巨大的帮助，当然，信息也很多，尽量不要打印，除非分析陷入僵局
             Java.perform(function () {
                 var bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
                 console.log("nBacktrace:n" + bt);
             });

             // 打印参数
             if (arguments.length) console.log();
             for (var j = 0; j < arguments.length; j++) {
                 console.log("arg[" + j + "]: " + arguments[j]);
             }

             //打印返回值
             var retval = this[targetMethod].apply(this, arguments); // rare crash (Frida bug?)
             console.log("nretval: " + retval);
             console.warn("n*** exiting " + targetMethod);
             return retval;
         }
     }
 }

*/

// find and trace all methods declared in a Java Class
function traceClass(targetClass) {
    var hook = Java.use(targetClass);
    var methods = hook.class.getDeclaredMethods();
    hook.$dispose;

    var parsedMethods = [];
    methods.forEach(function (method) {
        parsedMethods.push(method.toString().replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
    });

    var targets = uniqBy(parsedMethods, JSON.stringify);
    targets.forEach(function (targetMethod) {
        traceMethod(targetClass + "." + targetMethod);
    });
}

function traceClassMember(targetClass) {
    var hook = Java.use(targetClass);
    var fields = hook.class.getDeclaredFields();
    fields.forEach(function (targetField) {
        var value = -1;
// 获取字段的名称
        var fieldName = targetField.getName();
// 获取字段的修饰符
        var modifiers = targetField.getModifiers();//如：private、static、final等
// 与某个具体的修饰符进行比较
//         var isStatic = Modifier.isStatic(fieldValue)//看此修饰符是否为静态(static)
// 获取字段的声明类型
        var fieldType = targetField.getType();//返回的是一个class
        value = hook.targetField;
// 与某个类型进行比较
        console.log("Name: " + fieldName + " modifiers:" + modifiers + " Type:" + fieldType + " value=" + value);
    });
    hook.$dispose;
}

// 追踪本地库函数
// function traceModule(impl, name) {
//     console.log("Tracing " + name);
//     //frida的Interceptor
//     Interceptor.attach(impl, {
//         onEnter: function (args) {
//
//             console.warn("n*** entered " + name);
//             //打印调用栈
//             console.log("nBacktrace:n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
//                 .map(DebugSymbol.fromAddress).join("n"));
//         },
//         onLeave: function (retval) {
//             //打印返回值
//             console.log("nretval: " + retval);
//             console.warn("n*** exiting " + name);
//
//         }
//     });
// }
// trace a specific Java Method
function traceMethod(targetClassMethod) {
    var delim = targetClassMethod.lastIndexOf(".");
    if (delim === -1) return;

    var targetClass = targetClassMethod.slice(0, delim)
    var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)

    var hook = Java.use(targetClass);
    var overloadCount = hook[targetMethod].overloads.length;

    console.log("Tracing " + targetClassMethod + " [" + overloadCount + " overload(s)]");

    for (var i = 0; i < overloadCount; i++) {

        hook[targetMethod].overloads[i].implementation = function () {
            console.warn("\n*** entered " + targetClassMethod);

            // print backtrace
            // Java.perform(function() {
            //	var bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            //	console.log("\nBacktrace:\n" + bt);
            // });

            // print args
            if (arguments.length) console.log();
            for (var j = 0; j < arguments.length; j++) {
                console.log("arg[" + j + "]: " + arguments[j]);
            }

            // print retval
            var retval = this[targetMethod].apply(this, arguments); // rare crash (Frida bug?)
            console.log("\nretval: " + retval);
            console.warn("\n*** exiting " + targetClassMethod);
            return retval;
        }
    }
}

// remove duplicates from array
function uniqBy(array, key) {
    var seen = {};
    return array.filter(function (item) {
        var k = key(item);
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
}

setTimeout(function () {
    Java.perform(function () {
        // console.log("n[*] enumerating classes...");
        // Java.enumerateLoadedClasses({
        //     onMatch: function (_className) {
        //         if (_className.split(".")[1] == "example") {
        //             console.log("[->]t" + _className);
        //         }
        //     },
        //     onComplete: function () {
        //         console.log("[*] class enuemration complete");
        //     }
        // });
        // outDescJavaClass("com.example.myfridatest.MainActivity");
        // traceClassMember('com.example.myfridatest.MainActivity');
        changeValue("com.example.myfridatest.MainActivity");
        // onclick();
        // enumMethods("com.example.myfridatest.MainActivity", "setExple")
        // a.forEach(function (s) {
        //     console.log(s);
        // });
        // Java.choose("com.example.myfridatest.MainActivity", {
        //     onMatch: function (instance) {
        //         console.log("[*] " + " com.example.myfridatest.MainActivity instance found" + " :=> '" + instance + "'");
        //     },
        //     onComplete: function () {
        //         console.log("[*] -----");
        //     }
        // });
    });
});

function on_message(message, data) {
    if (message['type'] === 'send')
        print("[*] {0}".format(message['payload']));
    else {
        print(message)
    }
}

function outDescJavaClass(className) {
    var jClass = Java.use(className);
    console.log(JSON.stringify({
        _name: className,
        _methods: Object.getOwnPropertyNames(jClass.__proto__).filter(function (m) {
            return !m.startsWith('$') // filter out Frida related special properties
                || m === 'class' || m === 'constructor' // optional
        }),
        _fields: jClass.class.getFildes.map(function (f) {
            return f.toString()
        })
    }, null, 2));
}

function onclick() {
    // Function to hook is defined here
    var clicklistener = Java.use('com.example.myfridatest.MainActivity$1');
    // Whenever button is clicked
    var onClick = clicklistener.onClick;
    onClick.implementation = function (v) {
        // Show a message to know that the function got called
        send("send");
        // Call the original onClick handler
        onClick.call(this, v);

    };
}

function changeValue(activity) {
    // if (activity.cnt)
    // activity.cnt.value = 999;
    // Log to the console that it's done, and we should have the flag!
    // var MainActivity = Java.use(activity);
    //     // MainActivity.setExple.overload('java.lang.String').implementation = function (s1) {
    //     //     this.cnt.value = 10290;
    //     //     console.log('执行重载:' + JSON.stringify(this.cnt.value));
    //     //     return this.setExple(s1);
    //     // };
    Java.choose(activity, {
        onMatch: function (instance) {
            console.log("找到MainActivity instance:" + instance.cnt.value);
            instance.cnt.value = 228;
            instance.button.value.setTextColor(-13814538);
            var ClassName = Java.use("java.lang.String");
            var newstring = ClassName.$new("哈哈大苏打哈");
            var StringClass = Java.use("java.lang.CharSequence");
            var NewTypeClass = Java.cast(newstring, StringClass);
            console.log("WODE" + JSON.stringify(NewTypeClass))
            instance.button.value.setText(NewTypeClass);
            instance.button.value.invalidate();
        },
        onComplete: function () {
            console.log("MainActivity 完成查找:");
        }

    });
}

function emuallClass() {
    Java.perform(function () {
        console.log("枚举所有类...");
        Java.enumerateLoadedClasses({
            onMatch: function (_className) {
                if (_className.split(".")[1] === "example") {
                    console.log("[->]t" + _className);
                }
            },
            onComplete: function () {
                console.log("枚举所有类 complete");
            }
        });

    });
}

// com.example.myfridatest