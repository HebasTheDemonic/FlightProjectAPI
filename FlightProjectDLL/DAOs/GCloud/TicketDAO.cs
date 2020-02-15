using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.SqlClient;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FlightProject.POCOs;

namespace FlightProject.DAOs
{
    internal class TicketDAOMSSQL : ITicketDAO
    {
        public void Add(Ticket t)
        {
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "ADD_TICKET";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter flightIdParameter = new SqlParameter();
                flightIdParameter.SqlDbType = SqlDbType.Int;
                flightIdParameter.SqlValue = t.FlightId;
                flightIdParameter.ParameterName = "@FLIGHT";

                SqlParameter customerIdParameter = new SqlParameter();
                customerIdParameter.SqlDbType = SqlDbType.Int;
                customerIdParameter.SqlValue = t.CustomerId;
                customerIdParameter.ParameterName = "@CUSTOMER";

                sqlCommand.Parameters.Add(flightIdParameter);
                sqlCommand.Parameters.Add(customerIdParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                connection.Close();
            }
        }

        public int DoesTicketExistByID(Ticket ticket)
        {
            int result = 0;
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "DOES_TICKET_EXIST_BY_ID";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter ticketIdParameter = new SqlParameter();
                ticketIdParameter.SqlDbType = SqlDbType.Int;
                ticketIdParameter.SqlValue = ticket.Id;
                ticketIdParameter.ParameterName = "@ID";

                SqlParameter returnValueParameter = new SqlParameter();
                returnValueParameter.SqlDbType = SqlDbType.Int;
                returnValueParameter.Direction = ParameterDirection.ReturnValue;
                returnValueParameter.ParameterName = "@VALUE";

                sqlCommand.Parameters.Add(ticketIdParameter);
                sqlCommand.Parameters.Add(returnValueParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                result = (int)returnValueParameter.Value;
                connection.Close();
            }
            return result;
        }

        public int DoesTicketExistByCustomerAndFlight(Ticket ticket)
        {
            int result = 0;
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "DOES_TICKET_EXIST_BY_CUSTOMER_AND_FLIGHT";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter ticketIdParameter = new SqlParameter();
                ticketIdParameter.SqlDbType = SqlDbType.Int;
                ticketIdParameter.SqlValue = ticket.FlightId;
                ticketIdParameter.ParameterName = "@FLIGHT";

                SqlParameter customerIdParameter = new SqlParameter();
                customerIdParameter.SqlDbType = SqlDbType.Int;
                customerIdParameter.SqlValue = ticket.CustomerId;
                customerIdParameter.ParameterName = "@CUSTOMER";

                SqlParameter returnValueParameter = new SqlParameter();
                returnValueParameter.SqlDbType = SqlDbType.Int;
                returnValueParameter.Direction = ParameterDirection.Output;
                returnValueParameter.ParameterName = "@VALUE";

                sqlCommand.Parameters.Add(customerIdParameter);
                sqlCommand.Parameters.Add(returnValueParameter);
                sqlCommand.Parameters.Add(ticketIdParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                result = (int)returnValueParameter.Value;
                connection.Close();
            }
            return result;
        }

        public Ticket Get(int id)
        {
            Ticket ticket = new Ticket();
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_TICKET_BY_ID";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter ticketIdParameter = new SqlParameter();
                ticketIdParameter.SqlDbType = SqlDbType.Int;
                ticketIdParameter.SqlValue = id;
                ticketIdParameter.ParameterName = "@ID";

                sqlCommand.Parameters.Add(ticketIdParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    ticket = new Ticket((int)sqlDataReader["ID"],
                                        (int)sqlDataReader["FLIGHT"],
                                        (int)sqlDataReader["CUSTOMER"]);
                }
                connection.Close();
            }
            return ticket;
        }

        public IList<Ticket> GetAll()
        {
            List<Ticket> tickets = new List<Ticket>();

            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_ALL_TICKETS";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    Ticket ticket = new Ticket((int)sqlDataReader["ID"],
                                        (int)sqlDataReader["FLIGHT"],
                                        (int)sqlDataReader["CUSTOMER"]);
                    tickets.Add(ticket);
                }
                connection.Close();
            }
            return tickets;
        }

        public IList<Ticket> GetAllTicketsByCustomer(Customer customer)
        {
            List<Ticket> tickets = new List<Ticket>();

            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_ALL_TICKETS_BY_CUSTOMER";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter customerIdParameter = new SqlParameter();
                customerIdParameter.SqlDbType = SqlDbType.Int;
                customerIdParameter.SqlValue = customer.Id;
                customerIdParameter.ParameterName = "@CUSTOMER";

                sqlCommand.Parameters.Add(customerIdParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    Ticket ticket = new Ticket((int)sqlDataReader["ID"],
                                        (int)sqlDataReader["FLIGHT"],
                                        (int)sqlDataReader["CUSTOMER"]);
                    tickets.Add(ticket);
                }
                connection.Close();
            }
            return tickets;
        }

        public IList<Ticket> GetAllTicketsByFlight(int flightId)
        {
            List<Ticket> tickets = new List<Ticket>();

            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_ALL_TICKETS_BY_FLIGHT";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter flightIdParameter = new SqlParameter();
                flightIdParameter.SqlDbType = SqlDbType.Int;
                flightIdParameter.SqlValue = flightId;
                flightIdParameter.ParameterName = "@FLIGHT";


                sqlCommand.Parameters.Add(flightIdParameter);

                connection.Open();

                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    Ticket ticket = new Ticket((int)sqlDataReader["ID"],
                                        (int)sqlDataReader["FLIGHT"],
                                        (int)sqlDataReader["CUSTOMER"]);
                    tickets.Add(ticket);
                }
                connection.Close();
            }
            return tickets;
        }

        public Ticket GetTicketID(Ticket ticket)
        {
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_TICKET_ID";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter flightIdParameter = new SqlParameter();
                flightIdParameter.SqlDbType = SqlDbType.Int;
                flightIdParameter.SqlValue = ticket.FlightId;
                flightIdParameter.ParameterName = "@FLIGHT";

                SqlParameter customerIdParameter = new SqlParameter();
                customerIdParameter.SqlDbType = SqlDbType.Int;
                customerIdParameter.SqlValue = ticket.CustomerId;
                customerIdParameter.ParameterName = "@CUSTOMER";

                sqlCommand.Parameters.Add(customerIdParameter);
                sqlCommand.Parameters.Add(flightIdParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    ticket = new Ticket((int)sqlDataReader["ID"],
                                        ticket.FlightId,
                                        ticket.CustomerId);
                }
                connection.Close();
            }
            return ticket;
        }

        public void Remove(Ticket t)
        {
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand
                {
                    Connection = connection,
                    CommandText = "REMOVE_TICKET",
                    CommandType = CommandType.StoredProcedure
                };

                SqlParameter IdParameter = new SqlParameter
                {
                    SqlDbType = SqlDbType.Int,
                    SqlValue = t.Id,
                    ParameterName = "@ID"
                };

                sqlCommand.Parameters.Add(IdParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                connection.Close();
            }
        }

        public void Update(Ticket t)
        {
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "UPDATE_TICKET";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter flightIdParameter = new SqlParameter();
                flightIdParameter.SqlDbType = SqlDbType.Int;
                flightIdParameter.SqlValue = t.FlightId;
                flightIdParameter.ParameterName = "@FLIGHT";

                SqlParameter customerIdParameter = new SqlParameter();
                customerIdParameter.SqlDbType = SqlDbType.Int;
                customerIdParameter.SqlValue = t.CustomerId;
                customerIdParameter.ParameterName = "@CUSTOMER";

                sqlCommand.Parameters.Add(flightIdParameter);
                sqlCommand.Parameters.Add(customerIdParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                connection.Close();
            }
        }
    }
}
