package burp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class BurpExtender implements IBurpExtender, ISessionHandlingAction {
    private static final String SESSION_ID_KEY = "X-Custom-Session-Id:";
    private static final byte[] SESSION_ID_KEY_BYTES = SESSION_ID_KEY.getBytes();
    private static final byte[] CRLF = new byte[] {'\r', '\n'};

    IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Custom Session Tokens Example");

        callbacks.registerSessionHandlingAction(this);
    }

    @Override
    public String getActionName() {
        return "Use session token from macro";
    }

    @Override
    public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
        // 获取宏请求，如果没有就中断 action
        if (macroItems.length == 0) return;

        // 获取宏返回的最后一个响应
        final byte[] finalResponse = macroItems[macroItems.length-1].getResponse();
        if (finalResponse == null) return;

        final List<String> headers = helpers.analyzeResponse(finalResponse).getHeaders();

        // 从宏响应中提取 session token
        String sessionToken = null;
        for (String header : headers) {
            if (!header.startsWith(SESSION_ID_KEY)) continue;

            sessionToken = header.substring(SESSION_ID_KEY.length()).trim();
        }

        if (sessionToken == null) return;

        final byte[] req = currentRequest.getRequest();

        // 确定 token 值在请求中的具体位置
        final int sessionTokenKeyStart = helpers.indexOf(req, SESSION_ID_KEY_BYTES, false, 0, req.length);
        final int sessionTokenKeyEnd   = helpers.indexOf(req, CRLF, false, sessionTokenKeyStart, req.length);

        // 用宏返回的 token 重新构造请求
        currentRequest.setRequest(join(
                Arrays.copyOfRange(req, 0, sessionTokenKeyStart),
                helpers.stringToBytes(String.format("%s %s", SESSION_ID_KEY, sessionToken)),
                Arrays.copyOfRange(req, sessionTokenKeyEnd, req.length)
        ));
    }

    // 拼接多个字节数组
    private static byte[] join(byte[]... arrays) {
        // 确定拼接后的总长度
        int len = 0;
        for (byte[] arr : arrays)
            len += arr.length;

        byte[] result = new byte[len];

        // 逐个字符添加到新数组中
        int index = 0;
        for (byte[] arr : arrays)
            for (byte b : arr)
                result[index++] = b;

        return result;
    }
}
