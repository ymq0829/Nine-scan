
input.go代码解析

1.flag包的使用
通过 flag.String 函数定义了一个名为 targets 的命令行字符串选项，三个参数的含义分别是：
第一个参数 "targets"：命令行选项名称，运行程序时需通过 -targets 传入对应值（如 ./app -targets "192.168.1.1,192.168.1.2"）；
第二个参数 ""：选项的默认值，若运行程序时未指定 -targets，则 targetsFlag 指向的值为空字符串；
第三个参数：选项的说明文档，当运行程序传入 -h 或 --help 时，会打印该说明，帮助用户了解参数用途。
另外，flag.String 函数的返回值是 *string 类型（字符串指针），而非直接的 string 类型，targetsFlag 存储的是指向实际参数值的内存地址，后续需通过 *targetsFlag 取值

flag 包定义参数后，必须调用 flag.Parse() 函数才能完成命令行参数的解析