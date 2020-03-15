/*
 *  Copyright (C) Esaph, Julian Auguscik - All Rights Reserved
 *  * Unauthorized copying of this file, via any medium is strictly prohibited
 *  * Proprietary and confidential
 *  * Written by Julian Auguscik <esaph.re@gmail.com>, March  2020
 *
 */

import java.io.File;
import java.math.BigInteger;
import java.security.SecureRandom;

public class EsaphStoringHandler
{
    public String generatePID()
    {
        SecureRandom random = new SecureRandom();
        return new BigInteger(130, random).toString(32);
    }

    public File getStoringFile(String PID, String PATH)
    {
        File file = new File(PATH + File.separator + getFolderFilePath(PID));
        file.getParentFile().mkdirs();
        return file;
    }

    public File getTempFile(String prefix, long ThreadUID) //jpg oder mp4, datei format.
    {
        return new File(EsaphStoragePaths.dirTEMP + ThreadUID +
                "-" + System.currentTimeMillis() + "." + prefix);
    }

    private String getFolderFilePath(String mainDirectory) //Überprüft auch automatisch ob das datei Limit erreicht wurde, wenn ja dann wird ein neuer ordner angelegt.
    {
        String DIRECTORY = mainDirectory.replace(".", "");
        StringBuilder stringBuilder = new StringBuilder();
        for(int counter = 0; counter < DIRECTORY.length(); counter++)
        {
            stringBuilder.append(DIRECTORY.substring(counter, counter+1));
            stringBuilder.append(File.separator);
        }
        stringBuilder.append(mainDirectory);
        return stringBuilder.toString();
    }
}
