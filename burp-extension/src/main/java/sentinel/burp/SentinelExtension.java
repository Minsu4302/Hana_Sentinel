package sentinel.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Burp 확장 진입점. 등록과 연결만 한다((A) §2.9).
 * 1부는 확장 이름을 정하고 로드 사실을 한 줄 남긴다. 아무것도 전송하지 않는다.
 */
public final class SentinelExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Sentinel");
        api.logging().logToOutput("Sentinel extension loaded");
    }
}
