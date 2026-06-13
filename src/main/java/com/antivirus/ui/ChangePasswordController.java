package com.antivirus.ui;

import com.antivirus.db.DatabaseManager;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.stage.Stage;

/**
 * Contrôleur pour la boîte de dialogue de changement de mot de passe.
 */
public class ChangePasswordController {

    @FXML
    private PasswordField oldPasswordField;

    @FXML
    private PasswordField newPasswordField;

    @FXML
    private PasswordField confirmPasswordField;

    @FXML
    private Button changeButton;

    @FXML
    private Button cancelButton;

    @FXML
    private Label errorLabel;

    private String currentUsername;
    private Stage stage;

    public void setUsername(String username) {
        this.currentUsername = username;
    }

    public void setStage(Stage stage) {
        this.stage = stage;
    }

    @FXML
    private void handleChangePassword() {
        String oldPassword = oldPasswordField.getText();
        String newPassword = newPasswordField.getText();
        String confirmPassword = confirmPasswordField.getText();

        if (oldPassword.isEmpty() || newPassword.isEmpty() || confirmPassword.isEmpty()) {
            showError("Veuillez remplir tous les champs");
            return;
        }

        if (!newPassword.equals(confirmPassword)) {
            showError("Les nouveaux mots de passe ne correspondent pas");
            return;
        }

        if (newPassword.length() < 6) {
            showError("Le mot de passe doit contenir au moins 6 caractères");
            return;
        }

        DatabaseManager dbManager = DatabaseManager.getInstance();
        if (dbManager.changePassword(currentUsername, oldPassword, newPassword)) {
            // Succès - fermer la fenêtre
            stage.close();
        } else {
            showError("Ancien mot de passe incorrect");
        }
    }

    @FXML
    private void handleCancel() {
        stage.close();
    }

    private void showError(String message) {
        errorLabel.setText(message);
        errorLabel.setVisible(true);
    }
}
