package burp;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, IHttpListener {
    private static final String BAIDU = "www.baidu.com";
    private static final String BILIBILI = "www.bilibili.com";
    private Pattern hostRegex = Pattern.compile("(?<=[Hh]ost:).+");

    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 帮助处理 HTTP 请求的工具类
        helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Traffic Redirector Example");

        // 注册当前对象为 HTTP 事件监听器
        callbacks.registerHttpListener(this);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            IHttpService httpService = messageInfo.getHttpService();

            // 将百度的请求转发到哔哩哔哩
            if (BAIDU.equalsIgnoreCase(httpService.getHost())) {
                // 替换 Host 头
                Matcher matcher = hostRegex.matcher(new String(messageInfo.getRequest()));
                String newReq = matcher.replaceAll(BILIBILI);
                messageInfo.setRequest(newReq.getBytes(StandardCharsets.UTF_8));

                messageInfo.setHttpService(
                        helpers.buildHttpService(BILIBILI, httpService.getPort(), httpService.getProtocol())
                );
            }
        }
    }
}
