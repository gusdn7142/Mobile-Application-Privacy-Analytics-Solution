

// generic trace
function trace(pattern)
{
	// trace Java Class
	var found = false;
	Java.enumerateLoadedClasses({
		onMatch: function(aClass) {
			if (aClass.match(pattern)) {    //해당 문자열.match(찾을 단어). 인자에 포함된 문자 찾으면 이를 반환
				found = true;
				var className = aClass;
				traceClass(className);
			}
		},
		onComplete: function() {}
	});

	// trace Java Method (로드된 클래스가 없으면 메소드만 검색)
	if (!found) {
		try {
			traceMethod(pattern);
		}
		catch(err) { // catch non existing classes/methods
			console.error(err);
		}
	}
}

// find and trace all methods declared in a Java Class
function traceClass(targetClass)
{
	var hook = Java.use(targetClass);
	var methods = hook.class.getDeclaredMethods(); // Todo : hook 변수 타입 확인, method 변수 타입 확인
	hook.$dispose;

	var parsedMethods = [];
	methods.forEach(function(method) {
		parsedMethods.push(method.toString().replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]); // method 네임만 추출
	});

	// ["method1", "method2", "method3" ... ]
	var targets = uniqBy(parsedMethods, JSON.stringify); // 중복 제거
	targets.forEach(function(targetMethod) {
		traceMethod(targetClass + "." + targetMethod); // <trace()의 parameter>.메소드명
	});
}

// trace a specific Java Method
function traceMethod(targetClassMethod)
{
	var delim = targetClassMethod.lastIndexOf(".");
	if (delim === -1) return;

	var targetClass = targetClassMethod.slice(0, delim) // 패키지명.클래스명
	var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length) // 메소드명

	var hook = Java.use(targetClass);
	var overloadCount = hook[targetMethod].overloads.length;

	//console.log("Tracing " + targetClassMethod + " [" + overloadCount + " overload(s)]");

	for (var i = 0; i < overloadCount; i++) {

		hook[targetMethod].overloads[i].implementation = function() {
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
			console.error("\n*** exiting " + targetClassMethod);
			return retval;
		}
	}
}

// remove duplicates from array
function uniqBy(array, key)
{
        var seen = {};
        return array.filter(function(item) {
                var k = key(item);
                return seen.hasOwnProperty(k) ? false : (seen[k] = true);
		});
}

// usage examples
setTimeout(function() { // avoid java.lang.ClassNotFoundException

	Java.perform(function() {

		trace("com");   //앱 패키지명 입력


	});   
}, 0);