# HookMessageBox
编译后有三个执行文件
HookMessageBox.sys  驱动程序，用来和R3Hook通信修改页属性过写copy

R3Hook 用来和驱动通信传入要修改的线性地址

R3MessageTest 用来测试hook ,unhook是否正常。

1 没有运启动驱动安装hook 前正常运行 R3MessageTest.exe
![image](https://github.com/xiaomeng1/HookMessageBox/blob/master/image/%E6%AD%A3%E5%B8%B8%E8%BF%90%E8%A1%8CMessageBoxTest.png)


2 运行驱动 HookMessageBox.sys , 安装hook  R3Hook.exe 后再次运行 R3MessageTest.exe 
![image](https://github.com/xiaomeng1/HookMessageBox/blob/master/image/%E5%AE%89%E8%A3%85hook%E5%90%8E%E8%BF%90%E8%A1%8CMessageBoxTest.png)


3 卸载 hook 运行R3Hook.exe 后再次运行 R3MessageTest.exe 
![image](https://github.com/xiaomeng1/HookMessageBox/blob/master/image/%E5%8D%B8%E8%BD%BDhook%E5%90%8E%E8%BF%90%E8%A1%8CMessageBoxTest.png)

