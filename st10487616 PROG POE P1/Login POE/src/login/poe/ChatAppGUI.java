
package login.poe;

import javax.swing.*;
import java.awt.*;
import java.util.regex.*;

public class ChatAppGUI extends JFrame {
    private JTextField firstNameField, lastNameField, usernameField, phoneField;
    private JPasswordField passwordField;
    private JTextArea outputArea;
    private final JButton registerButton;
    private final JButton loginButton;

    // Store registered credentials
    private String storedUsername;
    private String storedPassword;
    private String storedFirstName;
    private String storedLastName;

    public ChatAppGUI() {
        setTitle("Chat App Registration & Login");
        setSize(450, 450);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new GridLayout(9, 2));

        // Input fields
        add(new JLabel("First Name:"));
        firstNameField = new JTextField();
        add(firstNameField);

        add(new JLabel("Last Name:"));
        lastNameField = new JTextField();
        add(lastNameField);

        add(new JLabel("Username:"));
        usernameField = new JTextField();
        add(usernameField);

        add(new JLabel("Password:"));
        passwordField = new JPasswordField();
        add(passwordField);

        add(new JLabel("Cell Phone (+27...):"));
        phoneField = new JTextField();
        add(phoneField);

        registerButton = new JButton("Register");
        loginButton = new JButton("Login");
        add(registerButton);
        add(loginButton);

        outputArea = new JTextArea();
        outputArea.setEditable(false);
        add(outputArea);

        // Register button logic
        registerButton.addActionListener(e -> {
            String firstName = firstNameField.getText();
            String lastName = lastNameField.getText();
            String username = usernameField.getText();
            String password = new String(passwordField.getPassword());
            String phone = phoneField.getText();

            Login user = new Login(firstName, lastName, username, password, phone);
            String result = user.registerUser();
            outputArea.setText(result);

            if (result.equals("User registered successfully.")) {
                storedUsername = username;
                storedPassword = password;
                storedFirstName = firstName;
                storedLastName = lastName;
            }
        });

        // Login button logic
        loginButton.addActionListener(e -> {
            String inputUsername = usernameField.getText();
            String inputPassword = new String(passwordField.getPassword());

            if (inputUsername.equals(storedUsername) && inputPassword.equals(storedPassword)) {
                outputArea.setText("Welcome " + storedFirstName + ", " + storedLastName + " it is great to see you again.");
            } else {
                outputArea.setText("Username or password incorrect, please try again.");
            }
        });

        setVisible(true);
    }

    public static void main(String[] args) {
        /*chatAppGUI*/
    }
}

// Login class for validation
class Login {
    private final String username;
    private final String password;
    private final String cellPhoneNumber;
    private final String firstName;
    private final String lastName;

    public Login(String firstName, String lastName, String username, String password, String cellPhoneNumber) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.username = username;
        this.password = password;
        this.cellPhoneNumber = cellPhoneNumber;
    }

    public boolean checkUserName() {
        return username.contains("_") && username.length() <= 5;
    }

    public boolean checkPasswordComplexity() {
        return password.length() >= 8 &&
               password.matches(".*[A-Z].*") &&
               password.matches(".*\\d.*") &&
               password.matches(".*[!@#$%^&*(),.?\":{}|<>].*");
    }

    public boolean checkCellPhoneNumber() {
        Pattern pattern = Pattern.compile("^\\+27\\d{9}$");
        Matcher matcher = pattern.matcher(cellPhoneNumber);
        return matcher.matches();
    }

    public String registerUser() {
        if (!checkUserName()) {
            return "Username is not correctly formatted, please ensure that your username contains an underscore and is no more than five characters in length.";
        }
        if (!checkPasswordComplexity()) {
            return "Password is not correctly formatted; please ensure that the password contains at least eight characters, a capital letter, a number, and a special character.";
        }
        if (!checkCellPhoneNumber()) {
            return "Cell phone number incorrectly formatted or does not contain international code.";
        }
        return "User registered successfully.";
    }
}
