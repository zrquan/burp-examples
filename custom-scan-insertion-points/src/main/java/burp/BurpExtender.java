package burp;

import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerInsertionPointProvider {
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Scan Insertion Points Example");

        callbacks.registerScannerInsertionPointProvider(this);
    }

    // 出入原始请求或响应，返回插入点列表
    @Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {
        IParameter dataParam = helpers.getRequestParameter(baseRequestResponse.getRequest(), "data");
        if (dataParam == null) return null;

        // 在 data 参数添加自定义的插入点，完成对 payload 的编码
        List<IScannerInsertionPoint> insertionPoints = new ArrayList<>();
        insertionPoints.add(new InsertionPoint(baseRequestResponse.getRequest(), dataParam.getValue()));
        return insertionPoints;
    }

    // 插入点
    private class InsertionPoint implements IScannerInsertionPoint {
        private byte[] baseRequest;
        private String prefix;
        private String baseValue;
        private String suffix;

        public InsertionPoint(byte[] baseRequest, String dataParam) {
            this.baseRequest = baseRequest;

            // 参数解码
            dataParam = helpers.bytesToString(helpers.base64Decode(helpers.urlDecode(dataParam)));

            // 用 start 和 end 定位 payload，并保存前后的内容
            int start = dataParam.indexOf("input=") + 6;
            prefix = dataParam.substring(0, start);
            int end = dataParam.indexOf("&", start);
            // end 不能超过总长度
            end = end == -1 ? dataParam.length() : end;
            baseValue = dataParam.substring(start, end);
            suffix = dataParam.substring(end, dataParam.length());
        }

        @Override
        public String getInsertionPointName() {
            return "Base64-wrapped input";
        }

        @Override
        public String getBaseValue() {
            return baseValue;
        }

        // 由插件处理扫描 payload
        @Override
        public byte[] buildRequest(byte[] payload) {
            String input = prefix + helpers.bytesToString(payload) + suffix;
            input = helpers.urlEncode(helpers.base64Encode(input));

            // 更新请求
            return helpers.updateParameter(baseRequest, helpers.buildParameter("data", input, IParameter.PARAM_BODY));
        }

        @Override
        public int[] getPayloadOffsets(byte[] payload) {
            // 插入点和 payload 的偏移量
            return null;
        }

        @Override
        public byte getInsertionPointType() {
            // 该插入点由插件添加
            return INS_EXTENSION_PROVIDED;
        }
    }
}
