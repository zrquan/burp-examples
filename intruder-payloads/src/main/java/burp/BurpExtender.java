package burp;

public class BurpExtender implements IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor{
    private IExtensionHelpers helpers;

    // 在实际测试时，根据需求构造 payloads
    private static final byte[][] PAYLOADS = {
        "|".getBytes(),
        "<script>alert(1)</script>".getBytes(),
    };

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Custom Intruder Payloads Example");

        // payloads 生成器
        callbacks.registerIntruderPayloadGeneratorFactory(this);
        // payloads 处理器
        callbacks.registerIntruderPayloadProcessor(this);
    }

    @Override
    public String getGeneratorName() {
        return "My custom payloads";
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        return new IntruderPayloadGenerator();
    }

    @Override
    public String getProcessorName() {
        return "Serialized input wrapper";
    }

    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        // 获取输入的源参数值
        String dataParam = helpers.bytesToString(helpers.base64Decode(helpers.urlDecode(baseValue)));

        // 确定 payload 插入位置的首尾
        int start = dataParam.indexOf("input=") + 6;
        if (start == -1) return currentPayload;
        String prefix = dataParam.substring(0, start);
        int end = dataParam.indexOf("&", start);
        if (end == -1)
            end = dataParam.length();
        String suffix = dataParam.substring(end, dataParam.length());

        // 插入自定义 payload，重新构建参数
        dataParam = prefix + helpers.bytesToString(currentPayload) + suffix;
        return helpers.stringToBytes(helpers.urlEncode(helpers.base64Encode(dataParam)));
    }

    class IntruderPayloadGenerator implements IIntruderPayloadGenerator {
        // payload 在字典的位置
        int payloadIndex;

        @Override
        public boolean hasMorePayloads() {
            return payloadIndex < PAYLOADS.length;
        }

        @Override
        public byte[] getNextPayload(byte[] baseValue) {
            // 返回 index 处的 payload，然后指向下一个 payload
            return PAYLOADS[payloadIndex++];
        }

        @Override
        public void reset() {
            // 重置
            payloadIndex = 0;
        }
    }
}
