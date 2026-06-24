package examples.java_rest_verification;

import java.io.StringReader;
import java.io.File;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;

public class RestController {
    @GetMapping("/workspace/{owner}/{name}")
    public String validateWorkspace(@PathVariable("owner") String owner, @PathVariable("name") String name) throws Exception {
        String command = "validate-workspace --owner " + owner + " --name " + name;
        Runtime.getRuntime().exec(command);
        return "ok";
    }

    @GetMapping("/file/{name}")
    public String readFile(@PathVariable("name") String name) {
        if (!name.matches("[A-Za-z0-9_.-]+")) {
            return "bad";
        }
        File file = new File("/safe/base/" + name);
        return file.getName();
    }

    @GetMapping("/xml")
    public String parseXml(@RequestBody String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.newDocumentBuilder().parse(new org.xml.sax.InputSource(new StringReader(xml)));
        return "ok";
    }
}

