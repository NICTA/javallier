package com.n1analytics.paillier.cli;

import org.apache.commons.cli.CommandLine;

import java.io.*;

public class OptionParsing {

  public static Writer processOutputOption(CommandLine line) {
    Writer output;
    String outputFilename = null;

    if(line.hasOption("output")) {
      outputFilename = line.getOptionValue("output");
    }

    output = (Writer) new BufferedWriter(new OutputStreamWriter(System.out));

    if (outputFilename != null && !"-".equals(outputFilename)) {
      try {
        output = (Writer) new PrintWriter(outputFilename);
      } catch (FileNotFoundException e) {
        System.err.println("Output file path not found. " + outputFilename);
        System.exit(1);
      }
    }

    return output;
  }
}
