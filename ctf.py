import frida, sys


def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)


jscode1 = """
Java.perform(function () {
  // Function to hook is defined here
  var clicklistener = Java.use('com.example.myfridatest.MainActivity$1');

  // Whenever button is clicked
  var onClick = clicklistener.onClick;
  onClick.implementation = function (v) {
    // Show a message to know that the function got called
    send('onClick');

    // Call the original onClick handler
    onClick.call(this, v);

    // Set our values after running the original onClick handler
    # this.m.value = 0;
    # this.n.value = 1;
    # this.cnt.value = 999;

    // Log to the console that it's done, and we should have the flag!
    console.log('Done:' + JSON.stringify(this.cnt));
  };
});
"""

jscode2 = """
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
"""

process = frida.get_usb_device().attach('com.example.myfridatest')
script = process.create_script(jscode1)
script.on('message', on_message)
print('[*] Running CTF')
script.load()
sys.stdin.read()
