package examples.insecure_siebel_java;

import java.io.File;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.sql.Connection;
import javax.xml.parsers.DocumentBuilderFactory;

public class IntegrationHandler {
    public void importPayload(InputStream input) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(input);
        stream.readObject();
    }

    public void runReport(String reportName) throws Exception {
        Runtime.getRuntime().exec("run-report " + reportName);
    }

    public void query(Connection connection, String accountId) throws Exception {
        connection.createStatement().executeQuery("select * from S_ORG_EXT where ROW_ID = '" + accountId + "'");
    }

    public File attachmentPath(String fileName) {
        return new File("/siebel/attachments/" + fileName);
    }

    public void parseXml(InputStream input) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder().parse(input);
    }
}
