using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FlightProject.POCOs;

namespace FlightProject.DAOs
{
    internal class CountryDAO : ICountryDAO
    {
        const string CONNECTIONSTRING = ConnectionStrings.MSSQLConnectionString;

        public void Add(Country t)
        {
            using (SqlConnection connection = new SqlConnection(CONNECTIONSTRING))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "ADD_COUNTRY";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter countryNameParameter = new SqlParameter();
                countryNameParameter.SqlDbType = SqlDbType.Char;
                countryNameParameter.SqlValue = t.CountryName;
                countryNameParameter.ParameterName = "@NAME";

                sqlCommand.Parameters.Add(countryNameParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                connection.Close();
            }
        }

        public Country Get(int id)
        {
            Country country = new Country();
            using (SqlConnection connection = new SqlConnection(CONNECTIONSTRING))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_COUNTRY_BY_ID";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter countryIdParameter = new SqlParameter();
                countryIdParameter.SqlDbType = SqlDbType.Int;
                countryIdParameter.SqlValue = id;
                countryIdParameter.ParameterName = "@ID";

                sqlCommand.Parameters.Add(countryIdParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    country = new Country((int)sqlDataReader["ID"],
                                          (string)sqlDataReader["NAME"]);
                }
                connection.Close();
            }
            return country;
        }

        public IList<Country> GetAll()
        {
            List<Country> countries = new List<Country>();

            using (SqlConnection connection = new SqlConnection(CONNECTIONSTRING))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_ALL_COUNTRIES";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    Country country = new Country((int)sqlDataReader["ID"],
                                                  (string)sqlDataReader["NAME"]);
                }
                connection.Close();
            }
            return countries;
        }

        public void Remove(Country t)
        {
            using (SqlConnection connection = new SqlConnection(CONNECTIONSTRING))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "REMOVE_COUNTRY";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter countryIdParameter = new SqlParameter();
                countryIdParameter.SqlDbType = SqlDbType.Int;
                countryIdParameter.SqlValue = t.ID;
                countryIdParameter.ParameterName = "@ID";

                sqlCommand.Parameters.Add(countryIdParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                connection.Close();
            }
        }

        public void Update(Country t)
        {
            using (SqlConnection connection = new SqlConnection(CONNECTIONSTRING))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "UPDATE_COUNTRY";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter countryNameParameter = new SqlParameter();
                countryNameParameter.SqlDbType = SqlDbType.Char;
                countryNameParameter.SqlValue = t.CountryName;
                countryNameParameter.ParameterName = "@NAME";

                SqlParameter countryIdParameter = new SqlParameter();
                countryIdParameter.SqlDbType = SqlDbType.Int;
                countryIdParameter.SqlValue = t.ID;
                countryIdParameter.ParameterName = "@ID";

                sqlCommand.Parameters.Add(countryNameParameter);
                sqlCommand.Parameters.Add(countryIdParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                connection.Close();
            }
        }
    }
}
