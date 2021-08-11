package burp;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IHttpListener, IProxyListener, IScannerListener, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 引用回调对象，以便在其他方法中使用
        this.callbacks = callbacks;

        callbacks.setExtensionName("Event Listeners Example");

        // 引用标准输出流，以便在其他方法中使用
        stdout = new PrintWriter(callbacks.getStdout(), true);

        // 注册当前对象为 HTTP 事件监听器，通常都需要注册这个监听器来处理请求和响应
        callbacks.registerHttpListener(this);
        // 注册当前对象为代理事件监听器
        callbacks.registerProxyListener(this);
        // 注册当前对象为扫描事件监听器
        callbacks.registerScannerListener(this);
        // 注册当前对象为插件状态事件监听器，通常用来释放资源
        callbacks.registerExtensionStateListener(this);
    }

    @Override
    public void extensionUnloaded() {
        stdout.println("插件卸载后打印这句话");
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        stdout.println(
                // 判断是请求还是响应
                (messageIsRequest ? "HTTP request to " : "HTTP response from ") +
                // 获取 HTTP 流量的主机名、端口、协议
                messageInfo.getHttpService() +
                // 判断流量是从哪个 Burp 组件来的
                " [" + callbacks.getToolName(toolFlag) + "]"
        );
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        stdout.println(
                (messageIsRequest ? "Proxy request to " : "Proxy response from ") +
                message.getMessageInfo().getHttpService()
        );
    }

    @Override
    public void newScanIssue(IScanIssue issue) {
        // 扫描器发现的漏洞名称
        stdout.println("New scan issue: " + issue.getIssueName());
    }
}
