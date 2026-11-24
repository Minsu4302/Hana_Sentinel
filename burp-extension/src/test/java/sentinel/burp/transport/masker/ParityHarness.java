package sentinel.burp.transport.masker;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * 동등성 하네스(src/test/java — 배포 jar 밖). Python 테스트(tests/test_java_masker_parity.py)가 오프라인 빌드 산출물을
 * java -cp로 실행한다. 클래스패스에는 gson만 둔다(error_prone_annotations 런타임 불필요를 매번 다시 확인).
 *
 * <p>인자: 추가 정책 파일 경로들(테스트 임시 폴더). 0번 정책 = 빌드가 넣은 정본 리소스, 1번부터 = 인자 순서.
 * stdin 한 줄 = 한 사례: "모드\t정책번호\tbase64(RawEnvelope JSON 바이트)".
 * stdout 한 줄 = 한 결과: "OK(\t이름\tbase64(Envelope 바이트))*" 또는 "REJECT\t사유코드" 또는 "POLICY_INVALID".
 * 원본·출력 값을 로그로 남기지 않는다. 디스크에 쓰지 않는다.
 */
public final class ParityHarness {
    private ParityHarness() {
    }

    public static void main(String[] args) throws IOException {
        List<Policy> policies = new ArrayList<>();
        boolean policyOk = true;
        try {
            policies.add(Policy.bundled());
            for (String path : args) {
                try (FileInputStream in = new FileInputStream(path)) {
                    policies.add(Policy.parse(in.readAllBytes()));
                }
            }
        } catch (Policy.PolicyInvalid e) {
            policyOk = false;
        }
        Base64.Decoder dec = Base64.getDecoder();
        Base64.Encoder enc = Base64.getEncoder();
        OutputStream out = new FileOutputStream(FileDescriptor.out);
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII));
        String line;
        while ((line = in.readLine()) != null) {
            if (line.isEmpty()) {
                continue;
            }
            String[] f = line.split("\t", -1);
            StringBuilder result = new StringBuilder();
            if (!policyOk) {
                result.append("POLICY_INVALID");
            } else {
                try {
                    RawEnvelope raw = RawEnvelopeJson.read(dec.decode(f[2]));
                    List<Masker.Output> outs = Masker.mask(raw, f[0], policies.get(Integer.parseInt(f[1])));
                    result.append("OK");
                    for (Masker.Output o : outs) {
                        result.append('\t').append(o.name()).append('\t').append(enc.encodeToString(o.bytes()));
                    }
                } catch (MaskerRejected e) {
                    result.setLength(0);
                    result.append("REJECT\t").append(e.code());
                }
            }
            result.append('\n');
            out.write(result.toString().getBytes(StandardCharsets.US_ASCII));
        }
        out.flush();
    }
}
