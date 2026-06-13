package com.antivirus.ui;

import com.antivirus.db.DatabaseManager;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.stage.Stage;

/**
 * Contrôleur pour l'écran de login.
 */
public class LoginController {

    @FXML
    private TextField usernameField;

    @FXML
    private PasswordField passwordField;

    @FXML
    private Button loginButton;

    @FXML
    private Button cancelButton;

    @FXML
    private Label errorLabel;

    private Stage stage;

    public void setStage(Stage stage) {
        this.stage = stage;
    }

    @FXML
    private void handleLogin() {
        String username = usernameField.getText().trim();
        String password = passwordField.getText();

        if (username.isEmpty() || password.isEmpty()) {
            showError("Veuillez remplir tous les champs");
            return;
        }

        DatabaseManager dbManager = DatabaseManager.getInstance();
        if (dbManager.authenticateUser(username, password)) {
            // Authentification réussie - ouvrir le dashboard
            try {
                FXMLLoader loader = new FXMLLoader(getClass().getResource("/fxml/dashboard.fxml"));
                Parent root = loader.load();

                Scene scene = new Scene(root, 1200, 750);
                scene.getStylesheets().add(getClass().getResource("/css/style.css").toExternalForm());

                Stage dashboardStage = new Stage();
                dashboardStage.setTitle("SeekMal — Antivirus & Monitoring");
                dashboardStage.setScene(scene);
                dashboardStage.setMinWidth(1000);
                dashboardStage.setMinHeight(650);

                // Arrêt propre lors de la fermeture
                DashboardController controller = loader.getController();
                controller.setCurrentUsername(username);
                dashboardStage.setOnCloseRequest(event -> controller.shutdown());

                dashboardStage.show();

                // Fermer la fenêtre de login
                stage.close();
            } catch (Exception e) {
                showError("Erreur lors du chargement du dashboard: " + e.getMessage());
                e.printStackTrace();
            }
        } else {
            showError("Nom d'utilisateur ou mot de passe incorrect");
        }
    }

    @FXML
    private void handleCancel() {
        System.exit(0);
    }

    private void showError(String message) {
        errorLabel.setText(message);
        errorLabel.setVisible(true);
    }
}
