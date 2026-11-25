package sentinel.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import sentinel.burp.capture.ContextMenu;
import sentinel.burp.transport.Settings;
import sentinel.burp.transport.Worker;
import sentinel.burp.ui.SettingsTab;

/**
 * Burp 확장 진입점. 등록과 연결만 한다((A) §2.9).
 * 설정 탭(토큰·포트·대기 상한·기한), 컨텍스트 메뉴 provider(사람이 고른 1건), 언로드 핸들러(실행기 종료·토큰 지우기)를 등록한다.
 * 2부 PR-2a는 아무것도 전송하지 않는다 — 메뉴 처리는 파싱·마스킹까지 하고 크기와 사유 코드만 로그에 남긴다.
 */
public final class SentinelExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Sentinel");
        Settings settings = new Settings();
        Worker worker = new Worker();
        api.userInterface().registerSuiteTab("Sentinel", new SettingsTab(settings).component());
        api.userInterface().registerContextMenuItemsProvider(
                new ContextMenu(worker, line -> api.logging().logToOutput("sentinel: " + line)));
        api.extension().registerUnloadingHandler(() -> {
            worker.shutdown();
            settings.clear();
        });
        api.logging().logToOutput("Sentinel extension loaded");
    }
}
