package burp;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener, IMessageEditorController {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    // UI 组件
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;

    // 日志列表
    private final List<LogEntry> log = new ArrayList<>();
    private IHttpRequestResponse currentItem;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Custom Logger Example");

        // 将 UI 相关的代码添加到 EDT 维护的事件队列中
        SwingUtilities.invokeLater(() -> {
            // 主面板，垂直拆分
            splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

            // 用当前 BurpExtender 对象管理表格数据，注意此时 this 指向的是 Runnable 对象
            Table logTable = new Table(BurpExtender.this);
            // 让日志面板可滚动
            JScrollPane scrollPane = new JScrollPane(logTable);
            // 在垂直拆分的面板中 setLeftComponent 指上面的拆分面板
            splitPane.setLeftComponent(scrollPane);

            // 选项卡面板，分别添加请求和响应两个选项卡
            JTabbedPane tabs = new JTabbedPane();
            // 获取和当前请求或响应绑定的消息编辑器
            requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
            responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
            // 将消息编辑器添加到选项卡
            tabs.addTab("Request", requestViewer.getComponent());
            tabs.addTab("Response", responseViewer.getComponent());
            // 选项卡面板设置在主面板下方
            splitPane.setRightComponent(tabs);

            // 用当前 Burp 的主题风格来绘制 UI 组件
            callbacks.customizeUiComponent(splitPane);
            callbacks.customizeUiComponent(logTable);
            callbacks.customizeUiComponent(scrollPane);
            callbacks.customizeUiComponent(tabs);

            // 添加 Burp 选项卡
            callbacks.addSuiteTab(BurpExtender.this);

            // 监听 HTTP 事件
            callbacks.registerHttpListener(BurpExtender.this);
        });
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // 获取响应时更新日志
        if (!messageIsRequest) {
            // 日志列表要同步更改
            synchronized (log) {
                int row = log.size();
                log.add(new LogEntry(
                        toolFlag,
                        // 用临时文件保存 HTTP 内容，节省内存
                        callbacks.saveBuffersToTempFiles(messageInfo),
                        // 请求 URL
                        helpers.analyzeRequest(messageInfo).getUrl())
                );
                // 添加一行日志
                fireTableRowsInserted(row, row);
            }
        }
    }

    @Override
    public IHttpService getHttpService() {
        return currentItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentItem.getResponse();
    }

    @Override
    public String getTabCaption() {
        return "Logger";
    }

    @Override
    public Component getUiComponent() {
        return splitPane;
    }

    @Override
    public int getRowCount() {
        return log.size();
    }

    @Override
    public int getColumnCount() {
        return 2;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = log.get(rowIndex);

        return switch (columnIndex) {
            case 0 -> callbacks.getToolName(logEntry.tool);
            case 1 -> logEntry.url.toString();
            default -> "";
        };
    }

    private class Table extends JTable {
        public Table (TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
            LogEntry logEntry = log.get(rowIndex);

            // 更新请求和响应内容
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);

            // 更新当前项的引用
            currentItem = logEntry.requestResponse;

            super.changeSelection(rowIndex, columnIndex, toggle, extend);
        }
    }

    // 用来表示一条 HTTP 日志的数据结构
    private static class LogEntry {
        final int tool;
        final IHttpRequestResponse requestResponse;
        final URL url;

        LogEntry (int tool, IHttpRequestResponse requestResponse, URL url) {
            this.tool = tool;
            this.requestResponse = requestResponse;
            this.url = url;
        }
    }
}