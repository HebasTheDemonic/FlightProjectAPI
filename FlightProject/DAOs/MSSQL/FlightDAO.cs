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
    internal class FlightDAO : IFlightDAO
    {
        public void Add(Flight t)
        {
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["MSSQLConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "ADD_FLIGHT";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter airlineParameter = new SqlParameter();
                airlineParameter.SqlDbType = SqlDbType.Int;
                airlineParameter.SqlValue = t.AirlineCompanyId;
                airlineParameter.ParameterName = "@AIRLINE";

                SqlParameter originCountryParameter = new SqlParameter();
                originCountryParameter.SqlDbType = SqlDbType.Int;
                originCountryParameter.SqlValue = t.OriginCountryId;
                originCountryParameter.ParameterName = "@ORIGIN";

                SqlParameter destinationCountryParameter = new SqlParameter();
                destinationCountryParameter.SqlDbType = SqlDbType.Int;
                destinationCountryParameter.SqlValue = t.DestinationCountryId;
                destinationCountryParameter.ParameterName = "@DESTINATION";

                SqlParameter departureTimeParmeter = new SqlParameter();
                departureTimeParmeter.SqlDbType = SqlDbType.DateTime;
                departureTimeParmeter.SqlValue = t.DepartureTime;
                departureTimeParmeter.ParameterName = "@DEPARTURE";

                SqlParameter landingTimeParameter = new SqlParameter();
                landingTimeParameter.SqlDbType = SqlDbType.DateTime;
                landingTimeParameter.SqlValue = t.LandingTime;
                landingTimeParameter.ParameterName = "@LANDING";

                SqlParameter totalTicketsParameter = new SqlParameter();
                totalTicketsParameter.SqlDbType = SqlDbType.Int;
                totalTicketsParameter.SqlValue = t.TotalTickets;
                totalTicketsParameter.ParameterName = "@TOTAL";

                sqlCommand.Parameters.Add(airlineParameter);
                sqlCommand.Parameters.Add(originCountryParameter);
                sqlCommand.Parameters.Add(destinationCountryParameter);
                sqlCommand.Parameters.Add(departureTimeParmeter);
                sqlCommand.Parameters.Add(landingTimeParameter);
                sqlCommand.Parameters.Add(totalTicketsParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                connection.Close();
            }
        }

        public int CheckRemainingSeatsOnFlight(int flightId)
        {
            int result = 0;
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["MSSQLConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "CHECK_REMAINING_SEATS_ON_FLIGHT";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter flightIdParameter = new SqlParameter();
                flightIdParameter.SqlDbType = SqlDbType.Int;
                flightIdParameter.SqlValue = flightId;
                flightIdParameter.ParameterName = "@ID";

                SqlParameter returnValueParameter = new SqlParameter();
                returnValueParameter.SqlDbType = SqlDbType.Int;
                returnValueParameter.Direction = ParameterDirection.Output;
                returnValueParameter.ParameterName = "@VALUE";

                sqlCommand.Parameters.Add(flightIdParameter);
                sqlCommand.Parameters.Add(returnValueParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                result = (int)returnValueParameter.Value;
                connection.Close();
            }
            return result;
        }

        public int DoesFlightExistByData(Flight flight)
        {
            int result = 0;
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["MSSQLConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "DOES_FLIGHT_EXIST_BY_DATA";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter originCountryParameter = new SqlParameter();
                originCountryParameter.SqlDbType = SqlDbType.Int;
                originCountryParameter.SqlValue = flight.OriginCountryId;
                originCountryParameter.ParameterName = "@ORIGIN";

                SqlParameter destinationCountryParameter = new SqlParameter();
                destinationCountryParameter.SqlDbType = SqlDbType.Int;
                destinationCountryParameter.SqlValue = flight.DestinationCountryId;
                destinationCountryParameter.ParameterName = "@DESTINATION";

                SqlParameter departureTimeParameter = new SqlParameter();
                departureTimeParameter.SqlDbType = SqlDbType.DateTime;
                departureTimeParameter.SqlValue = flight.DepartureTime;
                departureTimeParameter.ParameterName = "@DEPARTURE";

                SqlParameter landingTimeParameter = new SqlParameter();
                landingTimeParameter.SqlDbType = SqlDbType.DateTime;
                landingTimeParameter.SqlValue = flight.LandingTime;
                landingTimeParameter.ParameterName = "@LANDING";

                SqlParameter airlineIdParameter = new SqlParameter();
                airlineIdParameter.SqlDbType = SqlDbType.Int;
                airlineIdParameter.SqlValue = flight.AirlineCompanyId;
                airlineIdParameter.ParameterName = "@AIRLINE";

                SqlParameter returnValueParameter = new SqlParameter();
                returnValueParameter.SqlDbType = SqlDbType.Int;
                returnValueParameter.Direction = ParameterDirection.Output;
                returnValueParameter.ParameterName = "@VALUE";

                sqlCommand.Parameters.Add(originCountryParameter);
                sqlCommand.Parameters.Add(destinationCountryParameter);
                sqlCommand.Parameters.Add(departureTimeParameter);
                sqlCommand.Parameters.Add(landingTimeParameter);
                sqlCommand.Parameters.Add(airlineIdParameter);
                sqlCommand.Parameters.Add(returnValueParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                result = (int)returnValueParameter.Value;
                connection.Close();
            }
            return result;
        }

        public int DoesFlightExistById(int id)
        {
            int result = 0;
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["MSSQLConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "DOES_FLIGHT_EXIST_BY_ID";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter idParameter = new SqlParameter();
                idParameter.SqlDbType = SqlDbType.Int;
                idParameter.SqlValue = id;
                idParameter.ParameterName = "@ID";

                SqlParameter returnValueParameter = new SqlParameter();
                returnValueParameter.SqlDbType = SqlDbType.Int;
                returnValueParameter.Direction = ParameterDirection.Output;
                returnValueParameter.ParameterName = "@VALUE";

                sqlCommand.Parameters.Add(idParameter);
                sqlCommand.Parameters.Add(returnValueParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                result = (int)returnValueParameter.Value;
                connection.Close();
            }
            return result;
        }

        public Flight Get(int id)
        {
            Flight flight = new Flight();

            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["MSSQLConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_FLIGHT_BY_ID";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter flightIdParameter = new SqlParameter();
                flightIdParameter.SqlDbType = SqlDbType.Int;
                flightIdParameter.SqlValue = id;
                flightIdParameter.ParameterName = "@ID";

                sqlCommand.Parameters.Add(flightIdParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    flight = new Flight((int)sqlDataReader["ID"],
                                        (int)sqlDataReader["AIRLINE"],
                                        (int)sqlDataReader["ORIGIN"],
                                        (int)sqlDataReader["DESTINATION"],
                                        (DateTime)sqlDataReader["DEPARTURE"],
                                        (DateTime)sqlDataReader["LANDING"],
                                        (string)sqlDataReader["STATUS"],
                                        (int)sqlDataReader["TOTAL"],
                                        (int)sqlDataReader["REMAINING"]);
                }
                connection.Close();
            }
            return flight;
        }

        public IList<Flight> GetAll()
        {
            List<Flight> flights = new List<Flight>();
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["MSSQLConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_ALL_FLIGHTS";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    Flight flight = new Flight((int)sqlDataReader["ID"],
                                       (int)sqlDataReader["AIRLINE"],
                                       (int)sqlDataReader["ORIGIN"],
                                       (int)sqlDataReader["DESTINATION"],
                                       (DateTime)sqlDataReader["DEPARTURE"],
                                       (DateTime)sqlDataReader["LANDING"],
                                       (string)sqlDataReader["STATUS"],
                                       (int)sqlDataReader["TOTAL"],
                                       (int)sqlDataReader["REMAINING"]);
                    flights.Add(flight);
                }
                connection.Close();
            }
            return flights;
        }

        public IList<Flight> GetFlightsByAirlineCompany(AirlineCompany airline)
        {
            List<Flight> flights = new List<Flight>();
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["MSSQLConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_FLIGHTS_BY_AIRLINE";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter airlineParameter = new SqlParameter();
                airlineParameter.SqlDbType = SqlDbType.Int;
                airlineParameter.SqlValue = airline.Id;
                airlineParameter.ParameterName = "@AIRLINE";

                sqlCommand.Parameters.Add(airlineParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    Flight flight = new Flight((int)sqlDataReader["ID"],
                                       (int)sqlDataReader["AIRLINE"],
                                       (int)sqlDataReader["ORIGIN"],
                                       (int)sqlDataReader["DESTINATION"],
                                       (DateTime)sqlDataReader["DEPARTURE"],
                                       (DateTime)sqlDataReader["LANDING"],
                                       (string)sqlDataReader["STATUS"],
                                       (int)sqlDataReader["TOTAL"],
                                       (int)sqlDataReader["REMAINING"]);
                    flights.Add(flight);
                }
                connection.Close();
            }
            return flights;
        }

        public IList<Flight> GetFlightsByCustomer(Customer customer)
        {
            List<Flight> flights = new List<Flight>();

            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["MSSQLConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_FLIGHTS_BY_CUSTOMER";
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
                    Flight flight = new Flight((int)sqlDataReader["ID"],
                                       (int)sqlDataReader["AIRLINE"],
                                       (int)sqlDataReader["ORIGIN"],
                                       (int)sqlDataReader["DESTINATION"],
                                       (DateTime)sqlDataReader["DEPARTURE"],
                                       (DateTime)sqlDataReader["LANDING"],
                                       (string)sqlDataReader["STATUS"],
                                       (int)sqlDataReader["TOTAL"],
                                       (int)sqlDataReader["REMAINING"]);
                    flights.Add(flight);
                }
                connection.Close();
            }
            return flights;
        }

        public IList<Flight> GetFlightsByDepartureDate(DateTime departureDate)
        {
            List<Flight> flights = new List<Flight>();

            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["MSSQLConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_FLIGHTS_BY_DEPARTURE_DATE";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter departureTimeParameter = new SqlParameter();
                departureTimeParameter.SqlDbType = SqlDbType.DateTime;
                departureTimeParameter.SqlValue = departureDate;
                departureTimeParameter.ParameterName = "@DEPARTURE";

                sqlCommand.Parameters.Add(departureTimeParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    Flight flight = new Flight((int)sqlDataReader["ID"],
                                       (int)sqlDataReader["AIRLINE"],
                                       (int)sqlDataReader["ORIGIN"],
                                       (int)sqlDataReader["DESTINATION"],
                                       (DateTime)sqlDataReader["DEPARTURE"],
                                       (DateTime)sqlDataReader["LANDING"],
                                       (string)sqlDataReader["STATUS"],
                                       (int)sqlDataReader["TOTAL"],
                                       (int)sqlDataReader["REMAINING"]);
                    flights.Add(flight);
                }
                connection.Close();
            }
            return flights;
        }

        public IList<Flight> GetFlightsByDestinationCountry(int countryCode)
        {
            List<Flight> flights = new List<Flight>();

            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["MSSQLConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_FLIGHTS_BY_DESTINATION_COUNTRY";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter airlineParameter = new SqlParameter();
                airlineParameter.SqlDbType = SqlDbType.Int;
                airlineParameter.SqlValue = countryCode;
                airlineParameter.ParameterName = "@COUNTRY";

                sqlCommand.Parameters.Add(airlineParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    Flight flight = new Flight((int)sqlDataReader["ID"],
                                       (int)sqlDataReader["AIRLINE"],
                                       (int)sqlDataReader["ORIGIN"],
                                       (int)sqlDataReader["DESTINATION"],
                                       (DateTime)sqlDataReader["DEPARTURE"],
                                       (DateTime)sqlDataReader["LANDING"],
                                       (string)sqlDataReader["STATUS"],
                                       (int)sqlDataReader["TOTAL"],
                                       (int)sqlDataReader["REMAINING"]);
                    flights.Add(flight);
                }
                connection.Close();
            }
            return flights;
        }

        public IList<Flight> GetFlightsByLandingDate(DateTime landingDate)
        {
            List<Flight> flights = new List<Flight>();

            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["MSSQLConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_FLIGHTS_BY_LANDING_DATE";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter landingTimeParameter = new SqlParameter();
                landingTimeParameter.SqlDbType = SqlDbType.DateTime;
                landingTimeParameter.SqlValue = landingDate;
                landingTimeParameter.ParameterName = "@LANDING";

                sqlCommand.Parameters.Add(landingTimeParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    Flight flight = new Flight((int)sqlDataReader["ID"],
                                       (int)sqlDataReader["AIRLINE"],
                                       (int)sqlDataReader["ORIGIN"],
                                       (int)sqlDataReader["DESTINATION"],
                                       (DateTime)sqlDataReader["DEPARTURE"],
                                       (DateTime)sqlDataReader["LANDING"],
                                       (string)sqlDataReader["STATUS"],
                                       (int)sqlDataReader["TOTAL"],
                                       (int)sqlDataReader["REMAINING"]);
                    flights.Add(flight);
                }
                connection.Close();
            }
            return flights;
        }

        public IList<Flight> GetFlightsByOriginCountry(int countryCode)
        {
            List<Flight> flights = new List<Flight>();

            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["MSSQLConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_FLIGHTS_BY_ORIGIN_COUNTRY";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter airlineParameter = new SqlParameter();
                airlineParameter.SqlDbType = SqlDbType.Int;
                airlineParameter.SqlValue = countryCode;
                airlineParameter.ParameterName = "@COUNTRY";

                sqlCommand.Parameters.Add(airlineParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    Flight flight = new Flight((int)sqlDataReader["ID"],
                                       (int)sqlDataReader["AIRLINE"],
                                       (int)sqlDataReader["ORIGIN"],
                                       (int)sqlDataReader["DESTINATION"],
                                       (DateTime)sqlDataReader["DEPARTURE"],
                                       (DateTime)sqlDataReader["LANDING"],
                                       (string)sqlDataReader["STATUS"],
                                       (int)sqlDataReader["TOTAL"],
                                       (int)sqlDataReader["REMAINING"]);
                    flights.Add(flight);
                }
                connection.Close();
            }
            return flights;
        }

        public void Remove(Flight t)
        {
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["MSSQLConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "REMOVE_FLIGHT";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter flightIdParameter = new SqlParameter();
                flightIdParameter.SqlDbType = SqlDbType.Int;
                flightIdParameter.SqlValue = t.Id;
                flightIdParameter.ParameterName = "@ID";

                sqlCommand.Parameters.Add(flightIdParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                connection.Close();
            }
        }

        public void Update(Flight t)
        {
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["MSSQLConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "UPDATE_FLIGHT";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter idParameter = new SqlParameter();
                idParameter.SqlDbType = SqlDbType.Int;
                idParameter.SqlValue = t.Id;
                idParameter.ParameterName = "@ID";

                SqlParameter airlineParameter = new SqlParameter();
                airlineParameter.SqlDbType = SqlDbType.Int;
                airlineParameter.SqlValue = t.AirlineCompanyId;
                airlineParameter.ParameterName = "@AIRLINE";

                SqlParameter originCountryParameter = new SqlParameter();
                originCountryParameter.SqlDbType = SqlDbType.Int;
                originCountryParameter.SqlValue = t.OriginCountryId;
                originCountryParameter.ParameterName = "@ORIGIN";

                SqlParameter destinationCountryParameter = new SqlParameter();
                destinationCountryParameter.SqlDbType = SqlDbType.Int;
                destinationCountryParameter.SqlValue = t.DestinationCountryId;
                destinationCountryParameter.ParameterName = "@DESTINATION";

                SqlParameter departureTimeParmeter = new SqlParameter();
                departureTimeParmeter.SqlDbType = SqlDbType.DateTime;
                departureTimeParmeter.SqlValue = t.DepartureTime;
                departureTimeParmeter.ParameterName = "@DEPARTURE";

                SqlParameter landingTimeParameter = new SqlParameter();
                landingTimeParameter.SqlDbType = SqlDbType.DateTime;
                landingTimeParameter.SqlValue = t.LandingTime;
                landingTimeParameter.ParameterName = "@LANDING";

                SqlParameter totalTicketsParameter = new SqlParameter();
                totalTicketsParameter.SqlDbType = SqlDbType.Int;
                totalTicketsParameter.SqlValue = t.TotalTickets;
                totalTicketsParameter.ParameterName = "@TOTAL";

                SqlParameter remainingTicketsParameter = new SqlParameter();
                remainingTicketsParameter.SqlDbType = SqlDbType.Int;
                remainingTicketsParameter.SqlValue = t.RemainingTickets;
                remainingTicketsParameter.ParameterName = "@REMAINING";

                SqlParameter flightStatusParameter = new SqlParameter();
                flightStatusParameter.SqlDbType = SqlDbType.Char;
                flightStatusParameter.SqlValue = t.FlightStatus;
                flightStatusParameter.ParameterName = "@STATUS";

                sqlCommand.Parameters.Add(idParameter);
                sqlCommand.Parameters.Add(airlineParameter);
                sqlCommand.Parameters.Add(originCountryParameter);
                sqlCommand.Parameters.Add(destinationCountryParameter);
                sqlCommand.Parameters.Add(departureTimeParmeter);
                sqlCommand.Parameters.Add(landingTimeParameter);
                sqlCommand.Parameters.Add(totalTicketsParameter);
                sqlCommand.Parameters.Add(remainingTicketsParameter);
                sqlCommand.Parameters.Add(flightStatusParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                connection.Close();
            }
        }
    }
}
