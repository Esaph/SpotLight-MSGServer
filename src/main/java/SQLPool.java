/*
 *  Copyright (C) Esaph, Julian Auguscik - All Rights Reserved
 *  * Unauthorized copying of this file, via any medium is strictly prohibited
 *  * Proprietary and confidential
 *  * Written by Julian Auguscik <esaph.re@gmail.com>, March  2020
 *
 */

import java.util.*;

import com.mysql.jdbc.Connection;
import com.mysql.jdbc.PreparedStatement;

import java.sql.*;

public class SQLPool
{
	private volatile static boolean blocked = false;
	private static final String placeholder = "MessageServer(SQLPOOL): ";
	private final static int MAX_CONN = 40;
	private final Timer timerRefreezeConnections = new Timer();
	private static final String CONNECTION = "jdbc:mysql://localhost/LifeCapture?useSSL=false";
	private static final String SQLUser = "MSGServer";
	private static final String SQLPass = "H5XthxeP7OweqV2Dky4jwkYaxh47dEyOEXJqWibJkqSCA6OTon";
	private final Vector<Connection> connectionPool = new Vector<Connection>();

	public SQLPool()
	{
		initialize();
	}





	private class UnfreezeConnections extends TimerTask
	{
		private static final String ALIVE_QUERY = "SELECT 1 from Users LIMIT 1";

		@Override
		public void run()
		{
			for(int counter = 0; counter < SQLPool.MAX_CONN; counter++)
			{
				com.mysql.jdbc.PreparedStatement pr = null;
				try
				{
					Connection conn = getConnectionFromPool();
					pr = (PreparedStatement) conn.prepareStatement(ALIVE_QUERY);
					pr.execute();
					returnConnectionToPool(conn);
				}
				catch(Exception ec)
				{
					System.out.println(SQLPool.placeholder + "(UnfreezeConnections()): Keeping alive failed: " + ec);
					System.out.println(SQLPool.placeholder + "Reloading whole pool.");
					erasePool();
					break;
				}
				finally
				{
					try
					{
						if(pr != null)
						{
							pr.close();
						}
					}
					catch (Exception ec)
					{

					}
				}
				System.out.println(SQLPool.placeholder + "all connection ok.");
			}
		}
	}
	
	
	
	

	private void erasePool()
	{
		SQLPool.blocked = true;
		synchronized(connectionPool)
		{
			for(int counter = 0; counter < SQLPool.MAX_CONN; counter++)
			{
				try
				{
					Connection conn = (Connection) this.connectionPool.firstElement();
					this.connectionPool.removeElementAt(0);
					if(conn != null && !conn.isClosed())
					{
						conn.close();
					}
				}
				catch(Exception ec)
				{
					System.out.println(SQLPool.placeholder + "erasingPool(Exception()): " + ec);
				}
				
			}
			
			this.connectionPool.clear();
			System.out.println(SQLPool.placeholder + "Pool was erased.");
			this.initializeConnectionPool();
			SQLPool.blocked = false;
			System.out.println(SQLPool.placeholder + "Pool refreshed.");
		}
	}
	
	
	
	
	private void initialize()
	{
		//Here we can initialize all the information that we need
		initializeConnectionPool();
		timerRefreezeConnections.schedule(new UnfreezeConnections(), 0, 800000); //EVERY 15-MINUTES were the connections called.
	}

	private void initializeConnectionPool()
	{
		while(!checkIfConnectionPoolIsFull())
		{
			connectionPool.addElement(createNewConnectionForPool());
		}
		System.out.println(SQLPool.placeholder + "Connection Pool is full, added " + this.connectionPool.size() + " connections.");
	}

	private synchronized boolean checkIfConnectionPoolIsFull()
	{
		//Check if the pool size
		if(connectionPool.size() < SQLPool.MAX_CONN)
		{
			return false;
		}

		return true;
	}

	//Creating a connection
	private Connection createNewConnectionForPool()
	{
		Connection connection = null;
		try
		{
			connection = (Connection) DriverManager.getConnection(SQLPool.CONNECTION, SQLPool.SQLUser, SQLPool.SQLPass);
		}
		catch(SQLException sqle)
		{
			System.err.println(SQLPool.placeholder + "Exception(createNewConnectionsForPool()): "+ sqle);
			return null;
		}
		return connection;
	}

	public Connection getConnectionFromPool() throws InterruptedException, SQLException
	{
		if(!SQLPool.blocked)
		{
			synchronized(connectionPool)
			{
				while(connectionPool.size() <= 0)
				{
					connectionPool.wait();
				}
				
				Connection con = (Connection) connectionPool.remove(0);
				
				if(con == null || !con.isValid(10000))
				{
					if(con != null)
					{
						con.close();
					}
					con = createNewConnectionForPool(); //Added back in finally code.
				}
				
				return con;
			}
		}
		return null;
	}
	
	
	public Connection returnConnectionToPool(Connection connection)
	{
		if(!SQLPool.blocked)
		{
			synchronized(connectionPool)
			{
				if(connection != null)
				{
					connectionPool.addElement(connection);
					connectionPool.notify();
				}
			}
		}
		return null;
	}
}