import com.siemens.ct.exi.EXIFactory;
import com.siemens.ct.exi.GrammarFactory;
import com.siemens.ct.exi.api.sax.EXIResult;
import com.siemens.ct.exi.api.sax.EXISource;
import com.siemens.ct.exi.helpers.DefaultEXIFactory;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLReaderFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.StringReader;
import java.math.BigInteger;

import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import org.apache.commons.cli.*;
import java.io.ByteArrayInputStream;
//import javax.xml.bind.DatatypeConverter;


//import com.fluxlus.V2Gdecoder.binascii.BinAscii;

// based on: https://sourceforge.net/p/exificient/code/HEAD/tree/tags/exificient-0.9.4/src/sample/java/EXIficientDemo.java?format=raw
public class EXIEncode{

    //https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static void exi_encode(String input, String gram_xml_file, boolean filemode) throws Exception {
        InputSource xmlIs = null;

        EXIFactory exiFactory = DefaultEXIFactory.newInstance();
        exiFactory.setGrammars( GrammarFactory.newInstance().createGrammars( gram_xml_file ) );

        EXIResult exiResult = new EXIResult(exiFactory);   
        exiResult.setOutputStream( System.out );

        XMLReader xmlReader = XMLReaderFactory.createXMLReader();
        xmlReader.setContentHandler( exiResult.getHandler() );     
        
        if(filemode){
            File xmlIn  = new File( input );
            FileInputStream xmlIns = new FileInputStream( xmlIn );
            xmlIs = new InputSource( xmlIns );
        }
        else{
            xmlIs = new InputSource( new StringReader(input) );
        }
        xmlReader.parse( xmlIs );
    }

    public static void exi_decode(String input,  String gram_xml_file, boolean filemode) throws Exception {
        InputSource exiIs = null;
        EXIFactory exiFactory = DefaultEXIFactory.newInstance();
        exiFactory.setGrammars( GrammarFactory.newInstance().createGrammars( gram_xml_file ) );
        if (filemode){
            File exi = new File( input );
            FileInputStream exiIns = new FileInputStream( exi );
            exiIs = new InputSource( exiIns );
        }
        else{
            exiIs = new InputSource( new ByteArrayInputStream(hexStringToByteArray(input)) );
        }
        EXISource exiSource = new EXISource(exiFactory);
        exiSource.setXMLReader(exiSource.getXMLReader() );
        exiSource.setInputSource(exiIs);

        TransformerFactory.newInstance().newTransformer().transform(exiSource, new StreamResult(System.out));        
    }
    public static void main(String[] args) throws Exception{
        HelpFormatter formatter = new HelpFormatter();
        String gram_xml_file = null;

        Option opt_e = Option.builder("e").longOpt("encode").hasArg(false).desc("encode XML to EXI").build();
        Option opt_d = Option.builder("d").longOpt("decode").hasArg(false).desc("decode EXI to XML").build();
        Option opt_f = Option.builder("f").longOpt("file").hasArg(true).desc("input file").build();
        Option opt_o = Option.builder("o").longOpt("output").hasArg(true).desc("output file").build();
        Option opt_i = Option.builder("i").longOpt("intput").hasArg(true).desc("intput string").build();
        Option opt_g = Option.builder("g").longOpt("grammer").hasArg(true).desc("grammer file").build();

        Options options = new Options();
        
        options.addOption(opt_e);
        options.addOption(opt_d);
        options.addOption(opt_f);
        options.addOption(opt_o);
        options.addOption(opt_i);
        options.addOption(opt_g);

        CommandLineParser parser = new DefaultParser();

        if (args.length < 2){      
            formatter.printHelp("exixml", "", options, "", true);
            return;
        }

        try
        {
            CommandLine commandLine = parser.parse(options, args);
            if (commandLine.hasOption("g")){
                gram_xml_file = commandLine.getOptionValue("g");
            }
            else{
                throw new Exception("grammer file required.");
            }

            if (commandLine.hasOption("e"))
            {
                if (commandLine.hasOption("f")){
                    String input_xml_file = commandLine.getOptionValue("f");
                    exi_encode(input_xml_file, gram_xml_file, true);
                }
                else if(commandLine.hasOption("i")){
                    String input_xml_string = commandLine.getOptionValue("i");
                    exi_encode(input_xml_string, gram_xml_file, false);
                }
                else{
                    throw new Exception("-f or -i arg is required.");
                }
            }
            else if (commandLine.hasOption("d"))
            {
                if (commandLine.hasOption("f")){
                    String input_xml_file = commandLine.getOptionValue("f");
                    exi_decode(input_xml_file, gram_xml_file, true);
                }
                else if(commandLine.hasOption("i")){
                    String input_xml_string = commandLine.getOptionValue("i");
                    exi_decode(input_xml_string, gram_xml_file, false);
                }
                else{
                    throw new Exception("-f or -i arg is required.");
                }               
            }
            else{
                throw new Exception("-e or -d option required.");
            }
        }
        catch (Exception exception)
        {
            System.out.print("Parse error: ");
            System.out.println(exception.getMessage());
            formatter.printHelp("exixml", "", options, "", true);    
        }

    }

}
