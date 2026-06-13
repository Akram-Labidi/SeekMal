package com.antivirus;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import com.antivirus.ui.LoginController;

/**
 * Point d'entrée de l'application Antivirus.
 */
public class MainApp extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception {
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/fxml/login.fxml"));
        Parent root = loader.load();

        Scene scene = new Scene(root, 500, 450);
        scene.getStylesheets().add(getClass().getResource("/css/style.css").toExternalForm());

        primaryStage.setTitle("SeekMal — Connexion");
        primaryStage.setScene(scene);
        primaryStage.setResizable(false);
        primaryStage.show();

        // Passer la stage au contrôleur de login
        LoginController controller = loader.getController();
        controller.setStage(primaryStage);
    }

    public static void main(String[] args) {
        launch(args);
    }
}
