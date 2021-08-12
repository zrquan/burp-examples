package burp;

import java.awt.*;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
    IBurpExtenderCallbacks callbacks;
    IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Custom Editor Tab Example");

        // 注册当前对象为消息编辑器工厂
        callbacks.registerMessageEditorTabFactory(this);
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        // Burp 执行此方法获取一个消息编辑器
        return new Base64InputTab(controller, editable);
    }

    class Base64InputTab implements IMessageEditorTab {
        private boolean editable;
        // 由插件实现的 UI 组件，显示在对应的消息编辑器中
        private ITextEditor editor;
        // 保存请求报文
        private byte[] currentMessage;

        public Base64InputTab(IMessageEditorController controller, boolean editable) {
            this.editable = editable;

            // 创建 Burp 的文本编辑器
            editor = callbacks.createTextEditor();
            editor.setEditable(editable);
        }

        @Override
        public String getTabCaption() {
            return "Serialized input";
        }

        @Override
        public Component getUiComponent() {
            return editor.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            // 在包含 data 参数的请求中展示该消息编辑器
            return isRequest && helpers.getRequestParameter(content, "data") != null;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if (content == null) {
                editor.setText(null);
                editor.setEditable(false);
            }
            else {
                // 获取 data 参数的值
                IParameter param = helpers.getRequestParameter(content, "data");

                // 依次进行 URL 解密和 Base64 解密
                editor.setText(helpers.base64Decode(helpers.urlDecode(param.getValue())));
                editor.setEditable(editable);
            }

            currentMessage = content;
        }

        @Override
        public byte[] getMessage() {
            // 判断是否修改过内容，相应地更新请求或者响应
            if (editor.isTextModified()) {
                byte[] text = editor.getText();
                String input = helpers.urlEncode(helpers.base64Encode(text));

                // 将修改过的内容重新编码，赋值给请求体的 data 参数，返回更新后的请求报文
                return helpers.updateParameter(currentMessage, helpers.buildParameter("data", input, IParameter.PARAM_BODY));
            }
            return currentMessage;
        }

        @Override
        public boolean isModified() {
            return editor.isTextModified();
        }

        @Override
        public byte[] getSelectedData() {
            return editor.getSelectedText();
        }
    }
}
