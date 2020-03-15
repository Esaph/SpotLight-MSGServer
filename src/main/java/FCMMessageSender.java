/*
 *  Copyright (C) Esaph, Julian Auguscik - All Rights Reserved
 *  * Unauthorized copying of this file, via any medium is strictly prohibited
 *  * Proprietary and confidential
 *  * Written by Julian Auguscik <esaph.re@gmail.com>, March  2020
 *
 */

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.util.HashMap;
import javax.net.ssl.HttpsURLConnection;

import org.json.JSONObject;

public class FCMMessageSender
{
	private LogUtilsEsaph logUtilsMain;
	private static final String FCM_URL = "https://fcm.googleapis.com/fcm/send";
	private static final String FCM_SERVER_API_KEY = "AAAAjHK4vTY:APA91bELL7h5OE_Ym8EFEVi2V6gnFAIXUYdHJa7Ne1S-o65CgexqiDe2KR-QE97qadTgnYMtj4NoZbjNYQbivZRtjcB2Rz47ryyGSeSV-aXi1e0byOQAm-g3pHhHiiOFQnm8RBZNHAq1";


	public FCMMessageSender(LogUtilsEsaph logUtilsMain)
	{
		this.logUtilsMain = logUtilsMain;
	}

	public void sendWakeUp(String DFCM)
	{
		int responseCode = -1;
		String responseBody = null;
		try
		{
			this.logUtilsMain.writeLog("Sending FCM request");
			byte[] postData = getPostDataForWakeUpPhone(DFCM);

			URL url = new URL(FCMMessageSender.FCM_URL);
			HttpsURLConnection httpURLConnection = (HttpsURLConnection)url.openConnection();

			//set timeputs to 10 seconds
			httpURLConnection.setConnectTimeout(10000);
			httpURLConnection.setReadTimeout(10000);

			httpURLConnection.setDoOutput(true);
			httpURLConnection.setUseCaches(false);
			httpURLConnection.setRequestMethod("POST");
			httpURLConnection.setRequestProperty("Content-Type", "application/json");
			httpURLConnection.setRequestProperty("Content-Length", Integer.toString(postData.length));
			httpURLConnection.setRequestProperty("Authorization", "key="+FCM_SERVER_API_KEY);



			OutputStream out = httpURLConnection.getOutputStream();
			out.write(postData);
			out.flush();
			out.close();
			responseCode = httpURLConnection.getResponseCode();
			//success
			if (responseCode == FCMMessageSender.SC_OK)//HttpStatus.SC_OK
			{
				responseBody = convertStreamToString(httpURLConnection.getInputStream());
				this.logUtilsMain.writeLog("WAKE UP: " + responseBody);
			}
			//failure
			else
			{
				responseBody = convertStreamToString(httpURLConnection.getErrorStream());
				this.logUtilsMain.writeLog("WAKE UP failed for regId: " + " response: " + responseBody);
			}
		}
		catch (IOException ioe)
		{
			this.logUtilsMain.writeLog("IO Exception in sending FCM request. regId: ");
			ioe.printStackTrace();
		}
		catch (Exception e)
		{
			this.logUtilsMain.writeLog("Unknown exception in sending FCM request. regId: ");
			e.printStackTrace();
		}
	}

	private static final int SC_OK = 200;
	private static final String ID_COMMAND = "ID_CMD";

	public byte[] getPostDataForWakeUpPhone(String registrationId)
	{
		try
		{
			HashMap<String, String> dataMap = new HashMap<>();
			JSONObject payloadObject = new JSONObject();


			dataMap.put(FCMMessageSender.ID_COMMAND, "WUSH");

			JSONObject data = new JSONObject(dataMap);
			payloadObject.put("data", data);
			payloadObject.put("to", registrationId);
			payloadObject.put("priority", "high");

			return payloadObject.toString().getBytes();
		}
		catch(Exception ec)
		{
			this.logUtilsMain.writeLog("FCM (getPostData()): " + ec);
			return null;
		}
	}




	public String convertStreamToString (InputStream inStream)
	{
		try
		{
			InputStreamReader inputStream = new InputStreamReader(inStream);
			BufferedReader bReader = new BufferedReader(inputStream);

			StringBuilder sb = new StringBuilder();
			String line = null;
			while((line = bReader.readLine()) != null)
			{
				sb.append(line);
			}

			return sb.toString();
		}
		catch(Exception ecs)
		{
			this.logUtilsMain.writeLog("FCM (convertStreamToString()): " + ecs);
			return null;
		}

	}
}
		