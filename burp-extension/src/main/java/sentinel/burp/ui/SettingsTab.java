package sentinel.burp.ui;

import java.awt.Component;
import java.awt.GridLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import sentinel.burp.transport.Settings;

/**
 * 설정 탭 — (A) §2.9 토큰(v1.52). 비밀번호 입력란(토큰)·포트·대기 상한·기한과 '적용'·'지우기'만 둔다.
 * 라벨은 리터럴만 쓰고 서버 문자열을 표시하지 않는다(표시는 2부 PR-3, java_ui_plain_text). 토큰은 getPassword()의 char[]를
 * Settings로 넘기고 입력란은 비운다.
 */
public final class SettingsTab {
    private final JPanel panel = new JPanel(new GridLayout(0, 2, 6, 6));
    private final JPasswordField token = new JPasswordField(32);
    private final JTextField port = new JTextField(Integer.toString(Settings.DEFAULT_PORT), 6);
    private final JTextField queueLimit = new JTextField(Integer.toString(Settings.DEFAULT_QUEUE_LIMIT), 4);
    private final JTextField deadline = new JTextField(Integer.toString(Settings.DEFAULT_DEADLINE_SECONDS), 6);

    public SettingsTab(Settings settings) {
        JButton apply = new JButton("적용");
        JButton clear = new JButton("지우기");
        panel.add(new JLabel("토큰(서버 콘솔에 출력된 값)"));
        panel.add(token);
        panel.add(new JLabel("포트(127.0.0.1)"));
        panel.add(port);
        panel.add(new JLabel("대기 상한"));
        panel.add(queueLimit);
        panel.add(new JLabel("기한(초)"));
        panel.add(deadline);
        panel.add(apply);
        panel.add(clear);
        apply.addActionListener(e -> {
            char[] entered = token.getPassword();
            if (entered.length > 0) {
                settings.replaceToken(entered);
            }
            token.setText("");
            settings.apply(number(port.getText()), number(queueLimit.getText()), number(deadline.getText()));
        });
        clear.addActionListener(e -> {
            settings.clear();
            token.setText("");
        });
    }

    private static int number(String text) {
        try {
            return Integer.parseInt(text.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    public Component component() {
        return panel;
    }
}
