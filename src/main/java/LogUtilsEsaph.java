/*
 *  Copyright (C) Esaph, Julian Auguscik - All Rights Reserved
 *  * Unauthorized copying of this file, via any medium is strictly prohibited
 *  * Proprietary and confidential
 *  * Written by Julian Auguscik <esaph.re@gmail.com>, March  2020
 *
 */

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class LogUtilsEsaph
{
	public static boolean logInConsole = false;
	private String InetAddress;
	private String ServerType;
	private long UID;
	private FileWriter printer;
	private DateTimeFormatter dateTimeFormatter;
	
	
	public LogUtilsEsaph(final File rootPath, final String ServerType, final String InetAddress, final long UID) throws IOException
	{
		this.UID = UID;
		this.InetAddress = InetAddress;
		this.ServerType = ServerType;
		this.dateTimeFormatter = DateTimeFormatter.ofPattern("dd.MM.yyyy-HH:mm:ss");

		if(!LogUtilsEsaph.logInConsole)
		{
			EsaphStoringHandler esaphStoringHandler = new EsaphStoringHandler();
			File fileCurrent = esaphStoringHandler.getStoringFile(InetAddress, rootPath.getAbsolutePath());
			this.printer = new FileWriter(fileCurrent, true);
		}
	}

	public void closeFile()
	{
		try
		{
			this.printer.close();
		}
		catch(Exception ec)
		{
			try
			{
				File file = new File("/usr/server/bigProblem.log");
				FileWriter writer = new FileWriter(file, true);
				String toAppend = this.ServerType + "-" + this.dateTimeFormatter.format(LocalDateTime.now()) + "@" + this.InetAddress + ": " + ec + System.lineSeparator();
				writer.append(toAppend);
				writer.close();
			}
			catch(Exception ec2)
			{
				System.out.println(this.ServerType + "-" + this.dateTimeFormatter.format(LocalDateTime.now()) + "@" + this.InetAddress + ": Ja arschlecken 2.0 konnte datei nicht schlieﬂen:  " + ec2 + System.lineSeparator());
			}
		}
	}
	
	
	public synchronized void writeLog(String log)
	{
		try
		{
			String mMessage = this.ServerType
					+ "-"
					+ this.dateTimeFormatter.format(LocalDateTime.now())
					+ "\t@\t"
					+ this.InetAddress
					+ ", "
					+ this.UID
					+ ": "
					+ log
					+ System.lineSeparator();

			if(LogUtilsEsaph.logInConsole)
			{
				System.out.println(mMessage);
			}
			else
			{
				this.printer.append(mMessage);
				this.printer.flush();
			}
		}
		catch(Exception ec)
		{
			try
			{
				File file = new File("/usr/server/bigProblem.log");
				FileWriter writer = new FileWriter(file, true);
				String toAppend = this.ServerType + "-" + this.dateTimeFormatter.format(LocalDateTime.now()) + "@" + this.InetAddress + ": " + ec + System.lineSeparator();
				writer.append(toAppend);
				writer.close();
			}
			catch(Exception ec2)
			{
				System.out.println(this.ServerType + "-" + this.dateTimeFormatter.format(LocalDateTime.now()) + "@" + this.InetAddress + ": Ja arschlecken: " + ec2 + System.lineSeparator());
			}
		}
	}
	
	public void setUID(long UID)
	{
		this.UID = UID;
	}
}
