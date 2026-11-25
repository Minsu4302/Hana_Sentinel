package sentinel.burp.capture;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import java.awt.Component;
import java.util.List;
import java.util.function.Consumer;
import javax.swing.JMenuItem;
import sentinel.burp.capture.core.MetaSource;
import sentinel.burp.capture.core.Prepare;
import sentinel.burp.capture.core.Reasons;
import sentinel.burp.capture.core.Selection;
import sentinel.burp.transport.Worker;
import sentinel.burp.transport.masker.RawEnvelope;

/**
 * 컨텍스트 메뉴 provider — (A) §2.9 capture(`java_capture_human_selected`). 사람이 메뉴로 고른 1건만 넘겨받는다.
 * 이 클래스는 Montoya 이벤트에서 사실값(호출 위치·Repeater 출처·건수·응답 유무)과 바이트만 꺼낸다. 판정은 Selection.decide,
 * 처리는 단일 실행기(Worker)에서 한다 — EDT에서는 제출만 한다. 2부 PR-2a는 송신하지 않는다(로그 한 줄만).
 */
public final class ContextMenu implements ContextMenuItemsProvider {
    private final Worker worker;
    private final Consumer<String> log;

    public ContextMenu(Worker worker, Consumer<String> log) {
        this.worker = worker;
        this.log = log;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        JMenuItem item = new JMenuItem("Sentinel: prepare");
        item.addActionListener(e -> chosen(event));
        return List.of(item);
    }

    private void chosen(ContextMenuEvent event) {
        Selection.Origin origin;
        if (event.isFrom(InvocationType.MESSAGE_EDITOR_REQUEST, InvocationType.MESSAGE_EDITOR_RESPONSE)) {
            origin = Selection.Origin.EDITOR;
        } else if (event.isFrom(InvocationType.MESSAGE_VIEWER_REQUEST, InvocationType.MESSAGE_VIEWER_RESPONSE)) {
            origin = Selection.Origin.VIEWER;
        } else {
            origin = Selection.Origin.LIST;
        }
        List<HttpRequestResponse> picked = origin == Selection.Origin.LIST ? event.selectedRequestResponses()
                : event.messageEditorRequestResponse().map(m -> List.of(m.requestResponse())).orElse(List.of());
        HttpRequestResponse one = picked.size() == 1 ? picked.get(0) : null;
        String refusal = Selection.decide(origin, event.isFromTool(ToolType.REPEATER), picked.size(),
                one != null && one.hasResponse());
        if (refusal != null) {
            log.accept(refusal);
            return;
        }
        byte[] request = one.request().toByteArray().getBytes();
        byte[] response = one.response().toByteArray().getBytes();
        String host = one.httpService().host();
        int port = one.httpService().port();
        boolean secure = one.httpService().secure();
        RawEnvelope.Meta meta = MetaSource.now();
        if (!worker.submit(() -> log.accept(Prepare.run(request, response, host, port, secure, meta)))) {
            log.accept(Reasons.CLIENT_QUEUE_FULL);
        }
    }
}
