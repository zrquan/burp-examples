package burp;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {

    /**
     * 插件类必须实现 IBurpExtender 接口，类名和包名也是固定的
     *
     * Burp 加载插件时会调用这个方法，传入包含一组回调方法的对象
     * 开发者可以在插件中通过这些回调方法使用 Burp 的各种功能，和内置组件进行交互
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 插件名称
        callbacks.setExtensionName("Hello World Example");

        // 输出面板和错误信息的输出流
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);

        // 在 Extender -> Output 打印文本
        stdout.println("Hello output");
        // 在 Extender -> Errors 打印文本
        stderr.println("Hello errors");

        // Dashboard 第三象限
        callbacks.issueAlert("Hello allerts");

        // 在 Extender -> Errors 抛出异常信息
        throw new RuntimeException("Hello exceptions");
    }
}
