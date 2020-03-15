/*
 *  Copyright (C) Esaph, Julian Auguscik - All Rights Reserved
 *  * Unauthorized copying of this file, via any medium is strictly prohibited
 *  * Proprietary and confidential
 *  * Written by Julian Auguscik <esaph.re@gmail.com>, March  2020
 *
 */

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map.Entry;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.json.JSONArray;
import org.json.JSONObject;
import com.mysql.jdbc.Connection;
import com.mysql.jdbc.PreparedStatement;

public class MessageServer extends Thread
{
	private static ConcurrentHashMap<Long, ClientMessagingSession> clientSessionList = new ConcurrentHashMap<Long, ClientMessagingSession>();
	private final HashMap<String, Integer> connectionMap = new HashMap<String, Integer>();
	private static final int port = 1030;
	private static final String placeholder = "MessageServer: ";
	private SSLServerSocket serverSocket;
	private SQLPool pool;
	private LogUtilsEsaph serverMainThreadLog;
	private static final String mainServerLogPath = "/usr/server/Log/MSGServer/";
	private static final String ServerType = "MessageServer";
	
	public MessageServer() throws IOException
	{
		serverMainThreadLog = new LogUtilsEsaph(new File(MessageServer.mainServerLogPath), MessageServer.ServerType, "127.0.0.1", -100);
		Timer timer = new Timer();
		timer.schedule(new ResetDDOSProtection(), 0, 60000);
		try
		{
			pool = new SQLPool();
			this.serverMainThreadLog.writeLog("Thread pool loaded.");
		}
		catch(Exception ec)
		{
			this.serverMainThreadLog.writeLog("Thread pool failed to load: " + ec);
		}
	}
	
	
	public void startMessageServer() throws IOException
	{
		try
		{
			this.initSSLKey();
		    SSLServerSocketFactory sslServerSocketFactory = this.sslContext.getServerSocketFactory();
		    this.serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(MessageServer.port);
		    this.serverMainThreadLog.writeLog("Succesfully started.");
			this.start();
		}
		catch(Exception io)
		{
			this.serverMainThreadLog.writeLog("Exception(Starting server): " + io);
			System.exit(0);
		}
	}
	
	
	private static final String KeystoreFilePath = "/usr/server/ECCMasterKey.jks";
	private static final String TrustStoreFilePath = "/usr/server/servertruststore.jks";
	private static final String KeystorePass = "8db3626e47";
	private static final String TruststorePassword = "842407c248";
	private SSLContext sslContext;
	
	private void initSSLKey() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException, KeyManagementException
	{
		this.serverMainThreadLog.writeLog(MessageServer.placeholder + "Setting up SSL-Encryption");
		KeyStore trustStore = KeyStore.getInstance("JKS");
		trustStore.load(new FileInputStream(MessageServer.TrustStoreFilePath), MessageServer.TruststorePassword.toCharArray());
		this.serverMainThreadLog.writeLog(MessageServer.placeholder + "SSL-Encryption TrustStore VALID.");
		KeyStore keystore = KeyStore.getInstance("JKS");
		keystore.load(new FileInputStream(MessageServer.KeystoreFilePath), MessageServer.KeystorePass.toCharArray());
		this.serverMainThreadLog.writeLog(MessageServer.placeholder + "SSL-Encryption Keystore VALID.");
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(keystore, MessageServer.KeystorePass.toCharArray());

		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509"); 
		tmf.init(trustStore);

		sslContext = SSLContext.getInstance("TLS"); 
		TrustManager[] trustManagers = tmf.getTrustManagers(); 
		sslContext.init(kmf.getKeyManagers(), trustManagers, null);
		this.serverMainThreadLog.writeLog(MessageServer.placeholder + "SSL-Encryption OK.");
	}
	

	private class ResetDDOSProtection extends TimerTask
	{
		@Override
	    public void run()
	    {	
	    	synchronized(connectionMap)
	    	{
	    		if(connectionMap.size() != 0)
	    		{
					serverMainThreadLog.writeLog("Clearing IP-HASHMAP");
	    			connectionMap.clear();
	    		}
	    	}
	    }
	}
	
	private static final ThreadPoolExecutor executorMainThread = new ThreadPoolExecutor(Runtime.getRuntime().availableProcessors(),
            100,
            15,
            TimeUnit.SECONDS,
            new LinkedBlockingDeque<Runnable>(100),
            new ThreadPoolExecutor.CallerRunsPolicy());
	
	private static final int maxThreadCountClientPool = 30000;
	private static final ExecutorService executorClientPool = Executors.newFixedThreadPool(MessageServer.maxThreadCountClientPool);
	
	private static final int MAX_CONN_PER_MINUTE = 30;
	@Override
	public void run()
	{
		while(true)
		{
			try
			{
				SSLSocket socket = (SSLSocket) serverSocket.accept();
				this.serverMainThreadLog.writeLog("Connection: " + socket.getInetAddress());
				if(socket.getInetAddress().toString().equals("/127.0.0.1"))
				{
					MessageServer.executorMainThread.submit(new InternalMessageSender(socket));
				}
				else
				{
					if(this.connectionMap.get(socket.getInetAddress().toString()) != null)
					{
						if(this.connectionMap.get(socket.getInetAddress().toString()) >= MessageServer.MAX_CONN_PER_MINUTE)
						{
							socket.close();
						}
						else
						{
							this.connectionMap.put(socket.getInetAddress().toString(),  this.connectionMap.get(socket.getInetAddress().toString()) + 1);
							this.serverMainThreadLog.writeLog("Connection: " + socket.getInetAddress());
							MessageServer.executorMainThread.execute(new ClientAccepter(socket));
						}
					}
					else
					{
						this.connectionMap.put(socket.getInetAddress().toString(), 1);
						this.serverMainThreadLog.writeLog("Connection: " + socket.getInetAddress());
						MessageServer.executorMainThread.execute(new ClientAccepter(socket));
					}
				}
			}
			catch(Exception ec)
			{
				this.serverMainThreadLog.writeLog("ACCEPT ERROR: " + ec);
			}
		}
	}
	
	
	
	private class InternalMessageSender extends Thread
	{
		private JSONObject jsonMessage;
		private JSONArray RECEIVERS;
		private Connection connection;
		private PrintWriter writer;
		private BufferedReader reader;
		private SSLSocket socket;
		
		private InternalMessageSender(SSLSocket socket)
		{
			this.socket = socket;
		}


		private String readDataCarefully(int bufferSize) throws Exception
		{
			String msg = this.reader.readLine();
			if(msg == null || msg.length() > bufferSize)
			{
				if(msg != null)
				{
					throw new Exception("Exception: msg " + msg + " length: " + msg.length() + ">" + bufferSize);
				}
				else
				{
					throw new Exception("Exception: msg " + msg + " length: null " + ">" + bufferSize);
				}
			}
			serverMainThreadLog.writeLog("MSG CLIENT: " + msg);
			return msg;
		}
		
		
		@Override	
		public void run()
		{
			try
			{
				serverMainThreadLog.writeLog("Internal connection.");
				this.writer = new PrintWriter(new OutputStreamWriter(this.socket.getOutputStream(), StandardCharsets.UTF_8), true);
				this.reader = new BufferedReader(new InputStreamReader(this.socket.getInputStream(), StandardCharsets.UTF_8));
				this.socket.setSoTimeout(10000);
				
				this.jsonMessage = new JSONObject(this.readDataCarefully(10000));
				this.connection = (Connection) pool.getConnectionFromPool();
				
				if(this.jsonMessage.getString("MCMD").equals(MessageServer.cmd_SendInternalMessage))
				{
					this.RECEIVERS = this.jsonMessage.getJSONArray("EMPF");
					this.jsonMessage.remove("EMPF");
					this.jsonMessage.remove("MCMD");
					for(int counter = 0; counter < this.RECEIVERS.length(); counter++) //BROADCAST.
					{
						JSONObject jsonObjectReceiver = this.RECEIVERS.getJSONObject(counter);
						long atUser = jsonObjectReceiver.getLong("REC_ID");
						ClientMessagingSession msgPartner = clientSessionList.get(atUser);

						Socket socket = null;
						serverMainThreadLog.writeLog("Sending Message to " + atUser);
						if(msgPartner != null)
						{
							try
							{
								socket = msgPartner.getSocketConnection();
								serverMainThreadLog.writeLog("Empfänger ist mit MessageServer verbunden.");
								
								synchronized(socket)
								{
									socket.setSoTimeout(5000);
									socket.setKeepAlive(false);
									PrintWriter writerConnection = msgPartner.getConnection();
									writerConnection.println(this.jsonMessage.toString());
									serverMainThreadLog.writeLog("Message sent to " + atUser);
									BufferedReader bfReplay = msgPartner.getReader();
									String antwort = bfReplay.readLine();
									
									serverMainThreadLog.writeLog("Antwort = " + antwort);
									
									if(!antwort.equals("1")) //Partner-Thread Nachricht erhalten
									{
										serverMainThreadLog.writeLog("Chatpartner hat die nachricht nicht bestätigt.");
										PreparedStatement prStoreMessage = null;
										try
										{
											prStoreMessage = (PreparedStatement) this.connection.prepareStatement(MessageServer.queryInsertNewMessage);
											prStoreMessage.setLong(1, atUser);
											prStoreMessage.setString(2, this.jsonMessage.toString());
											prStoreMessage.executeUpdate();
											socket.setTcpNoDelay(true);
											socket.setKeepAlive(true);

											msgPartner.stopMessagingSession();
											serverMainThreadLog.writeLog("Blabla user konnte erreicht werden, schmeiße ihn rauß.");
										}
										catch (Exception ec)
										{
											serverMainThreadLog.writeLog("Storing message failed: " + ec);
											msgPartner.stopMessagingSession();
										}
										finally {
											if(prStoreMessage != null)
											{
												prStoreMessage.close();
											}
										}
									}
									socket.setTcpNoDelay(true);
									socket.setKeepAlive(true);
								}
							}
							catch(Exception ec)
							{
								serverMainThreadLog.writeLog("Konnte nachricht nicht absenden, speichere in Datenbank: " + ec);
								PreparedStatement prStoreMessage = null;
								try
								{
									prStoreMessage = (PreparedStatement) this.connection.prepareStatement(MessageServer.queryInsertNewMessage);
									prStoreMessage.setLong(1, atUser);
									prStoreMessage.setString(2, this.jsonMessage.toString());
									prStoreMessage.executeUpdate();
									synchronized(socket)
									{
										msgPartner.stopMessagingSession();
										serverMainThreadLog.writeLog("Blabla user konnte erreicht werden, schmeiße ihn rauß.");
									}

									FCMMessageSender sender = new FCMMessageSender(serverMainThreadLog);
									sender.sendWakeUp(this.lookUpFCM(atUser)); //Wach auf dummkopf...!
								}
								catch (Exception ec1)
								{
									serverMainThreadLog.writeLog("Failed sending fcm: " + ec1);
								}
								finally
								{
									if(prStoreMessage != null)
									{
										prStoreMessage.close();
									}
								}
							}
						}
						else
						{
							serverMainThreadLog.writeLog("Nutzer hat keine Verbindung, sende FCM.");
							PreparedStatement prStoreMessage = null;
							try
							{
								prStoreMessage = (PreparedStatement) this.connection.prepareStatement(MessageServer.queryInsertNewMessage);
								prStoreMessage.setLong(1, atUser);
								prStoreMessage.setString(2, this.jsonMessage.toString());
								prStoreMessage.executeUpdate();
								FCMMessageSender sender = new FCMMessageSender(serverMainThreadLog);
								sender.sendWakeUp(this.lookUpFCM(atUser)); //Wach auf dummkopf...!
							}
							catch (Exception ec)
							{

							}
							finally
							{
								if(prStoreMessage != null)
								{
									prStoreMessage.close();
								}
							}
						}
					}
				}
				else if(this.jsonMessage.getString("MCMD").equals(MessageServer.cmd_SendInternalMessageFireAndForget))
				{
					this.RECEIVERS = this.jsonMessage.getJSONArray("EMPF");
					this.jsonMessage.remove("EMPF");
					this.jsonMessage.remove("MCMD");
					for(int counter = 0; counter < this.RECEIVERS.length(); counter++) //BROADCAST.
					{
						JSONObject jsonObjectReceiver = this.RECEIVERS.getJSONObject(counter);
						long atUser = jsonObjectReceiver.getLong("REC_ID");
						ClientMessagingSession msgPartner = clientSessionList.get(atUser);

						Socket socket = null;
						serverMainThreadLog.writeLog("Sending Message to " + atUser);
						if(msgPartner != null)
						{
							try
							{
								socket = msgPartner.getSocketConnection();
								serverMainThreadLog.writeLog("Empfänger ist mit MessageServer verbunden.");

								synchronized(socket)
								{
									socket.setSoTimeout(5000);
									socket.setKeepAlive(false);
									PrintWriter writerConnection = msgPartner.getConnection();
									writerConnection.println(this.jsonMessage.toString());
									serverMainThreadLog.writeLog("Message sent to " + atUser);
									BufferedReader bfReplay = msgPartner.getReader();
									String antwort = bfReplay.readLine();

									serverMainThreadLog.writeLog("Antwort = " + antwort);

									if(!antwort.equals("1")) //Partner-Thread Nachricht erhalten
									{
										serverMainThreadLog.writeLog("Chatpartner hat die nachricht nicht bestätigt.");
										try
										{
											socket.setTcpNoDelay(true);
											socket.setKeepAlive(true);
											msgPartner.stopMessagingSession();
											serverMainThreadLog.writeLog("Blabla user konnte erreicht werden, schmeiße ihn rauß.");
										}
										catch (Exception ec)
										{
											serverMainThreadLog.writeLog("Storing message failed: " + ec);
											msgPartner.stopMessagingSession();
										}
									}
									socket.setTcpNoDelay(true);
									socket.setKeepAlive(true);
								}
							}
							catch(Exception ec)
							{
								serverMainThreadLog.writeLog("Konnte nachricht nicht absenden, speichere in Datenbank: " + ec);
								try
								{
									synchronized(socket)
									{
										msgPartner.stopMessagingSession();
										serverMainThreadLog.writeLog("Blabla user konnte erreicht werden, schmeiße ihn rauß.");
									}
								}
								catch (Exception ec1)
								{
									serverMainThreadLog.writeLog("Failed sending fcm: " + ec1);
								}
							}
						}
					}
				}
				else if(this.jsonMessage.getString("MCMD").equals(MessageServer.cmd_SetNewAdDisplayCount))
				{
					int counterPerUser = this.jsonMessage.getInt("CPU");
					if(counterPerUser == 0)
					{
						counterPerUser = 1;
					}
					int totalDisplayAds = this.jsonMessage.getInt("TDC");
					int counter = 0;
					serverMainThreadLog.writeLog("Count per User: " + counterPerUser);
					serverMainThreadLog.writeLog("Total Ads to display: " + totalDisplayAds);
					JSONObject finalValueJson = new JSONObject();
					finalValueJson.put("CMD", "SNAV");
					finalValueJson.put("NV", counterPerUser);
					String message = finalValueJson.toString();
					
					 for (Entry<Long, ClientMessagingSession> entry : clientSessionList.entrySet())
					 {
						 if(totalDisplayAds > counter)
						 {
							  ClientMessagingSession session = entry.getValue();
							  if(session != null)
							  {
								  SSLSocket currentSocket = session.getSocketConnection();
								  synchronized(currentSocket)
								  {
									  try
									  {
										  PrintWriter writer = session.getConnection();
										  BufferedReader bfReplay = session.getReader();
										  writer.println(message);
										  bfReplay.readLine();
										  currentSocket.setTcpNoDelay(true);
										  currentSocket.setKeepAlive(true); 
									  }
									  catch(Exception ec)
									  {
										  serverMainThreadLog.writeLog("Sending new ad-value failed: " + ec);
									  }
								  }
							  }
						 }
						 counter++;
					 }
				}
				else if(this.jsonMessage.getString("MCMD").equals(MessageServer.cmd_ResetAds))
				{
					JSONObject finalValueJson = new JSONObject();
					finalValueJson.put("CMD", "DAAR");
					String message = finalValueJson.toString();
					 for (Entry<Long, ClientMessagingSession> entry : clientSessionList.entrySet())
					 {
						 ClientMessagingSession session = entry.getValue();
						  SSLSocket currentSocket = session.getSocketConnection();
						  synchronized(currentSocket)
						  {
							  try
							  {
								  PrintWriter writer = session.getConnection();
								  BufferedReader bfReplay = session.getReader();
								  writer.println(message);
								  bfReplay.readLine();
								  currentSocket.setTcpNoDelay(true);
								  currentSocket.setKeepAlive(true); 
							  }
							  catch(Exception ec)
							  {
								  serverMainThreadLog.writeLog("Sending reset ads failed: " + ec);
							  }
						  }
					 }
				}
				else if(this.jsonMessage.getString("MCMD").equals(MessageServer.cmd_getCurrentUserConnectedCount))
				{
					this.writer.println(clientSessionList.size());
				}
				
				serverMainThreadLog.writeLog("Internal handling done.");
				this.socket.close();
				this.writer.close();
				this.reader.close();
			}
			catch(Exception ec)
			{
				serverMainThreadLog.writeLog(MessageServer.placeholder + "-InternalMessageSender() FATAL ERROR(1): " + ec);
				serverMainThreadLog.writeLog(MessageServer.placeholder + "-InternalMessageSender() FATAL ERROR(2): MESSAGES LOST");
			}
			finally
			{
				this.connection = (Connection) pool.returnConnectionToPool(this.connection);
			}
		}
		
		

		private String lookUpFCM(long UID)
		{
			PreparedStatement prLookUpFCM = null;
			ResultSet lookUpResult = null;
			try
			{
				prLookUpFCM = (PreparedStatement) this.connection.prepareStatement(MessageServer.queryLookUpFCM);
				prLookUpFCM.setLong(1, UID);
				lookUpResult = prLookUpFCM.executeQuery();
				if(lookUpResult.next())
				{
					serverMainThreadLog.writeLog("FCM OK for " + UID);
					return lookUpResult.getString(1);
				}
				else
				{
					serverMainThreadLog.writeLog("FCM WRONG for " + UID);
					return "-1";
				}
			}
			catch(Exception ec)
			{
				serverMainThreadLog.writeLog("lookUpFCM(FatalError): " + ec);
				return "-1";
			}
			finally {
				try
				{
					if(prLookUpFCM != null)
					{
						prLookUpFCM.close();
					}

					if(lookUpResult != null)
					{
						lookUpResult.close();
					}
				}
				catch (Exception ec)
				{
					serverMainThreadLog.writeLog("lookUpFCM() failed finally block: " + ec);
				}
			}
		}
	}
	
	private static final String cmd_SendInternalMessage = "SE";
	private static final String cmd_SendInternalMessageFireAndForget = "SEFAF";
	private static final String cmd_SetNewAdDisplayCount = "NACV";
	private static final String cmd_ResetAds = "RAS";
	private static final String cmd_getCurrentUserConnectedCount = "GCUOC";
	private static final String queryLookUpFCM = "SELECT FCM FROM FirebaseCloudMessaging WHERE UID=?";
	private static final String queryLookUpUID = "SELECT UID FROM Users WHERE Benutzername=?";
	private static final String queryLookUpUnreceivedMessagesForUser = "SELECT * FROM Messages WHERE UID_RECEIVER=? ORDER BY TIME";
	private static final String queryDeleteSingleMessage = "DELETE FROM Messages WHERE UID_RECEIVER=? AND TIME=?";
	private static final String queryInsertNewMessage = "INSERT INTO Messages (UID_RECEIVER, MESSAGE) values (?, ?)";

	private class ClientAccepter extends Thread
	{
		private JSONObject jsonMessage;
		private LogUtilsEsaph loggerClientAccepter;
		private Connection connection;
		private PrintWriter writer;
		private BufferedReader reader;
		private final SSLSocket socket;
		private long ThreadUID;
		
		
		public ClientAccepter(SSLSocket socket) throws IOException
		{
			this.socket = socket;
		}
		
		
		@Override
		public void run()
		{
			try
			{
				this.loggerClientAccepter = new LogUtilsEsaph(new File(MessageServer.mainServerLogPath),
						MessageServer.ServerType,
						socket.getInetAddress().getHostAddress(), -1);
				
				this.loggerClientAccepter.writeLog("Handling Connection started.");
				this.writer = new PrintWriter(new OutputStreamWriter(this.socket.getOutputStream(), StandardCharsets.UTF_8), true);
				this.reader = new BufferedReader(new InputStreamReader(this.socket.getInputStream(), StandardCharsets.UTF_8));
				this.socket.setSoTimeout(20000);
				
				this.jsonMessage = new JSONObject(this.readDataCarefully(1500));
				this.connection = (Connection) pool.getConnectionFromPool();
				
				
				if(this.checkSID()) //Session wurde überprüft
				{
					this.writer.println("1");
					this.loggerClientAccepter.setUID(this.ThreadUID);
					this.loggerClientAccepter.writeLog(this.ThreadUID + " logged in chat server.");
						ClientMessagingSession lastSession = clientSessionList.get(this.ThreadUID);
						if(lastSession != null)
						{
							try
							{
								lastSession.stopMessagingSession();
							}
							catch(Exception ecKillingLastSession)
							{
								this.loggerClientAccepter.writeLog("Failed to Interrupt last Messaging Thread: " + ecKillingLastSession);
							}
						}
						
						try
						{
							synchronized(socket) //AUF DIE CONNECTION ZUM NUTZER, KANN NUR EINER GLEICHZEITIG ZUGREIFEN. SELBST WENN ES NUR UMS LESEN GEHT ODER DER CLIENT AN SICH BEFEHLER AUSFÜHREN WILL!
							{
								socket.setSoTimeout(8000);
								socket.setKeepAlive(false);

								PreparedStatement prMessageInbox = null;
								ResultSet result = null;

								try
								{
									prMessageInbox = (PreparedStatement) this.connection.prepareStatement(MessageServer.queryLookUpUnreceivedMessagesForUser);
									prMessageInbox.setLong(1, this.ThreadUID);
									result = prMessageInbox.executeQuery();
									while(result.next())
									{
										//ABRUFEN DER NACHRICHTEN, WENN INTERNET AUS WAR.
										this.writer.println(result.getString("MESSAGE"));
										String reply = this.readDataCarefully(2);
										if(reply.equals("1"))
										{
											PreparedStatement prDeleteMessages = (PreparedStatement) this.connection.prepareStatement(MessageServer.queryDeleteSingleMessage);
											prDeleteMessages.setLong(1, this.ThreadUID);
											prDeleteMessages.setTimestamp(2, result.getTimestamp("TIME"));
											prDeleteMessages.executeUpdate();
											prDeleteMessages.close();
										}
									}
									this.writer.println("EOF");
									socket.setTcpNoDelay(true);
									socket.setKeepAlive(true);
								}
								catch (Exception ec)
								{
									this.loggerClientAccepter.writeLog("Sending Inbox Messages failed: " + ec);
								}
								finally
								{
									if(prMessageInbox != null)
									{
										prMessageInbox.close();
									}

									if(result != null)
									{
										result.close();
									}
								}
							}
						}
						catch(Exception ec)
						{
							this.loggerClientAccepter.writeLog("Checking Inbox Messages failed: " + ec);
						}
						
						
						ClientMessagingSession session = new ClientMessagingSession(this.socket, this.writer, this.reader, this.ThreadUID, this.lookUpFCM(this.ThreadUID), this.loggerClientAccepter);
						MessageServer.executorClientPool.execute(session);
						clientSessionList.put(this.ThreadUID, session);
					}
				else
				{
					this.writer.println("-1");
				}
			}
			catch(Exception ec)
			{
				this.loggerClientAccepter.writeLog("ClientAccepter(FatalError): " + ec);
			}
			finally
			{
				this.connection = (Connection) pool.returnConnectionToPool(this.connection);
				if(this.loggerClientAccepter != null)
				{
					this.loggerClientAccepter.writeLog("Connection closed: " + this.socket.getInetAddress());
					this.loggerClientAccepter.closeFile();
				}
			}
		}


		private String readDataCarefully(int bufferSize) throws Exception
		{
			String msg = this.reader.readLine();
			if(msg == null || msg.length() > bufferSize)
			{
				throw new Exception();
			}
			this.loggerClientAccepter.writeLog("MSG CLIENT: " + msg);
			return msg;
		}


		private static final String QUERY_CHECK_SESSION = "SELECT SID FROM Sessions WHERE SID=? AND UID=? LIMIT 1";
		private boolean checkSession(long UID, String SID)
		{
			PreparedStatement qSID = null;
			ResultSet result = null;
			try
			{
				this.loggerClientAccepter.writeLog("Checking Session for UID " + UID);
				qSID = (PreparedStatement) this.connection.prepareStatement(ClientAccepter.QUERY_CHECK_SESSION);
				qSID.setString(1, SID);
				qSID.setLong(2, UID);
				result = qSID.executeQuery();
				if(result.next())
				{
					this.loggerClientAccepter.writeLog("Session gültig.");
					return true;
				}
				else
				{
					this.loggerClientAccepter.writeLog("Session ungültig.");
					return false;
				}
			}
			catch(Exception ec)
			{
				this.loggerClientAccepter.writeLog("checkSessionRealCheck(FatalError): " + ec);
				return false;
			}
			finally
			{
				try
				{
					if(qSID != null)
					{
						qSID.close();
					}

					if(result != null)
					{
						result.close();
					}
				}
				catch (Exception ec)
				{

				}
			}
		}
		
		
		
		

		private boolean checkSID()
		{
			try
			{
				long UID = this.jsonMessage.getLong("USRN");
				String SID = this.jsonMessage.getString("SID");
				if(UID > 0)
				{
					if(checkSession(UID, SID))
					{
						this.ThreadUID = UID;
						return true;
					}
					else
					{
						return false;
					}
				}
				else
				{
					this.loggerClientAccepter.writeLog("UID ist kleiner 0 oder gleich 0. Problem!");
					return false;
				}
			}
			catch(Exception ec)
			{
				this.loggerClientAccepter.writeLog("checkSession(FatalError): " + ec);
				return false;
			}
		}

		private String lookUpFCM(long UID)
		{
			PreparedStatement prLookUpFCM = null;
			ResultSet lookUpResult = null;
			try
			{
				prLookUpFCM = (PreparedStatement) this.connection.prepareStatement(MessageServer.queryLookUpFCM);
				prLookUpFCM.setLong(1, UID);
				lookUpResult = prLookUpFCM.executeQuery();
				if(lookUpResult.next())
				{
					loggerClientAccepter.writeLog("FCM OK for " + UID);
					return lookUpResult.getString(1);
				}
				else
				{
					loggerClientAccepter.writeLog("FCM WRONG for " + UID);
					return "-1";
				}
			}
			catch(Exception ec)
			{
				loggerClientAccepter.writeLog("lookUpFCM(FatalError): " + ec);
				return "-1";
			}
			finally {
				try
				{
					if(prLookUpFCM != null)
					{
						prLookUpFCM.close();
					}

					if(lookUpResult != null)
					{
						lookUpResult.close();
					}
				}
				catch (Exception ec)
				{
					loggerClientAccepter.writeLog("lookUpFCM() failed finally block: " + ec);
				}
			}
		}
	}
	
	
	
	
	public class ClientMessagingSession extends Thread
	{
		private static final int sleepTime = 300000;
		private boolean permissionToRun = true;
		private LogUtilsEsaph loggerMessagingSession;
		private static final String placeholder = "ClientMessagingSession: ";
		private BufferedReader reader;
		private PrintWriter writer;
		private final SSLSocket socket;
		private long ThreadId;
		
		private ClientMessagingSession(SSLSocket socket, PrintWriter writer, BufferedReader reader, long ThreadId, String FCM, LogUtilsEsaph loggerMessagingSession)
		{
			this.loggerMessagingSession = loggerMessagingSession;
			this.socket = socket;
			this.writer = writer;
			this.reader = reader;
			this.ThreadId = ThreadId;
		}

		private String readDataCarefully(int bufferSize) throws Exception
		{
			String msg = this.reader.readLine();
			if(msg == null || msg.length() > bufferSize)
			{
				if(msg != null)
				{
					throw new Exception("Exception: msg " + msg + " length: " + msg.length() + ">" + bufferSize);
				}
				else
				{
					throw new Exception("Exception: msg " + msg + " length: null " + ">" + bufferSize);
				}
			}
			return msg;
		}

		@Override
		public void run()
		{
			try
			{
				this.loggerMessagingSession.writeLog(ClientMessagingSession.placeholder + "Connection ready to chat: " + this.ThreadId);
				synchronized (this.socket)
				{
					this.writer.println("COK");
					this.socket.setKeepAlive(true);
					this.socket.setTcpNoDelay(true);
				}

				while(true)
				{
					if(this.permissionToRun)
					{
						Thread.sleep(ClientMessagingSession.sleepTime);
					}
					
					synchronized(this.socket)
					{
						if(this.permissionToRun)
						{
							this.socket.setSoTimeout(15000); //15 sekdunden timeout, 5 sekunden, waren echt ein wenig heftig.
							this.writer.println("H");
							if(this.readDataCarefully(1).equals("H"))
							{
								this.loggerMessagingSession.writeLog(ClientMessagingSession.placeholder + "Heartbeat successfully: " + this.ThreadId);
							}
							else
							{
								this.loggerMessagingSession.writeLog(ClientMessagingSession.placeholder + "Heartbeat failed: " + this.ThreadId);
								this.writer.close();
								this.socket.close();
								this.reader.close();
								break;
							}
							this.socket.setKeepAlive(true);
							this.socket.setTcpNoDelay(true);
						}
					}
				}
			}
			catch(Exception ec)
			{
				this.loggerMessagingSession.writeLog(ClientMessagingSession.placeholder + "Messaging-Session exception: " + this.ThreadId + " " + ec);
			}
			finally
			{
				try
				{
					this.loggerMessagingSession.closeFile();
					clientSessionList.remove(this.ThreadId);
					
					synchronized(this.socket)
					{
						this.socket.close();
						this.writer.close();
						this.reader.close();
					}
				}
				catch(Exception ecO)
				{
					this.loggerMessagingSession.writeLog("REMOVED THREAD FROM MAP FAILED--: " + this.ThreadId + ecO);
				}
			}
			this.loggerMessagingSession.writeLog("Chat connection closed and stopped " + this.ThreadId);
		}
		
		private void stopMessagingSession()
		{
			this.permissionToRun = false;
		}

		private SSLSocket getSocketConnection()
		{
			return this.socket;
		}

		private PrintWriter getConnection()
		{
			return this.writer;
		}

		private BufferedReader getReader()
		{
			return this.reader;
		}
	}
}
