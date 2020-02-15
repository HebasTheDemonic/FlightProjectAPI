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
    internal class AirlineDAOMSSQL : IAirlineDAO
    {
        public void Add(AirlineCompany t)
        {
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "ADD_AIRLINE_COMPANY";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter usernameParameter = new SqlParameter();
                usernameParameter.SqlDbType = SqlDbType.Char;
                usernameParameter.SqlValue = t.UserName;
                usernameParameter.ParameterName = "@USER";

                SqlParameter passwordParameter = new SqlParameter();
                passwordParameter.SqlDbType = SqlDbType.Char;
                passwordParameter.SqlValue = t.Password;
                passwordParameter.ParameterName = "@PASS";

                SqlParameter companyNameParameter = new SqlParameter();
                companyNameParameter.SqlDbType = SqlDbType.Char;
                companyNameParameter.SqlValue = t.AirlineName;
                companyNameParameter.ParameterName = "@NAME";

                SqlParameter originCountryParameter = new SqlParameter();
                originCountryParameter.SqlDbType = SqlDbType.Char;
                originCountryParameter.SqlValue = t.OriginCountry;
                originCountryParameter.ParameterName = "@CODE";

                sqlCommand.Parameters.Add(usernameParameter);
                sqlCommand.Parameters.Add(passwordParameter);
                sqlCommand.Parameters.Add(companyNameParameter);
                sqlCommand.Parameters.Add(originCountryParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                connection.Close();
            }
        }

        public int DoesAirlineCompanyExist(AirlineCompany airlineCompany)
        {
            int result = 0;
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "DOES_AIRLINE_COMPANY_EXIST";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter usernameParameter = new SqlParameter();
                usernameParameter.SqlDbType = SqlDbType.Char;
                usernameParameter.SqlValue = airlineCompany.UserName;
                usernameParameter.ParameterName = "@USER";

                SqlParameter returnValueParameter = new SqlParameter();
                returnValueParameter.SqlDbType = SqlDbType.Int;
                returnValueParameter.Direction = ParameterDirection.Output;
                returnValueParameter.ParameterName = "@VALUE";

                sqlCommand.Parameters.Add(usernameParameter);
                sqlCommand.Parameters.Add(returnValueParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                result = (int)returnValueParameter.Value;
                connection.Close();
            }
            return result;
        }

        public AirlineCompany Get(int id)
        {
            AirlineCompany airlineCompany = new AirlineCompany();

            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_AIRLINE_COMPANY_BY_ID";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter idParameter = new SqlParameter();
                idParameter.SqlDbType = SqlDbType.Int;
                idParameter.SqlValue = id;
                idParameter.ParameterName = "@ID";

                sqlCommand.Parameters.Add(idParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    airlineCompany = new AirlineCompany((int)sqlDataReader["ID"],
                                                        (string)sqlDataReader["NAME"],
                                                        (string)sqlDataReader["USER"],
                                                        (string)sqlDataReader["PASS"],
                                                        (int)sqlDataReader["COUNTRY"]);
                }
                connection.Close();
            }
            return airlineCompany;
        }

        public AirlineCompany GetAirlineCompanybyUsername(string userName)
        {
            AirlineCompany airlineCompany = new AirlineCompany();

            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_AIRLINE_COMPANY_BY_USERNAME";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter usernameParameter = new SqlParameter();
                usernameParameter.SqlDbType = SqlDbType.Char;
                usernameParameter.SqlValue = userName;
                usernameParameter.ParameterName = "@USER";

                sqlCommand.Parameters.Add(usernameParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    airlineCompany = new AirlineCompany((int)sqlDataReader["ID"],
                                                         (string)sqlDataReader["NAME"],
                                                         (string)sqlDataReader["USER"],
                                                         (string)sqlDataReader["PASS"],
                                                         (int)sqlDataReader["COUNTRY"]);
                }
                connection.Close();
            }
            return airlineCompany;
        }

        public IList<AirlineCompany> GetAll()
        {
            List<AirlineCompany> airlineCompanies = new List<AirlineCompany>();

            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_ALL_AIRLINE_COMPANIES";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    AirlineCompany airlineCompany = new AirlineCompany((int)sqlDataReader["ID"],
                                                        (string)sqlDataReader["NAME"],
                                                        (string)sqlDataReader["USER"],
                                                        (string)sqlDataReader["PASS"],
                                                        (int)sqlDataReader["COUNTRY"]);
                    airlineCompanies.Add(airlineCompany);
                }
                connection.Close();
            }
            return airlineCompanies;
        }

        public IList<AirlineCompany> GetAllAirlinesByCountry(int countryId)
        {
            List<AirlineCompany> airlineCompanies = new List<AirlineCompany>();

            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_ALL_AIRLINE_COMPANIES_BY_COUNTRY";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter countryIdParameter = new SqlParameter();
                countryIdParameter.SqlDbType = SqlDbType.Int;
                countryIdParameter.SqlValue = countryId;
                countryIdParameter.ParameterName = "@ID";

                sqlCommand.Parameters.Add(countryIdParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    AirlineCompany airlineCompany = new AirlineCompany((int)sqlDataReader["ID"],
                                                        (string)sqlDataReader["NAME"],
                                                        (string)sqlDataReader["USER"],
                                                        (string)sqlDataReader["PASS"],
                                                        (int)sqlDataReader["COUNTRY"]);
                    airlineCompanies.Add(airlineCompany);
                }
                connection.Close();
            }
            return airlineCompanies;
        }

        public void Remove(AirlineCompany t)
        {
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "REMOVE_AIRLINE_COMPANY";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter idParameter = new SqlParameter();
                idParameter.SqlDbType = SqlDbType.Int;
                idParameter.SqlValue = t.Id;
                idParameter.ParameterName = "@ID";

                sqlCommand.Parameters.Add(idParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                connection.Close();
            }
        }

        public void Update(AirlineCompany t)
        {
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "UPDATE_AIRLINE_COMPANY";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter usernameParameter = new SqlParameter();
                usernameParameter.SqlDbType = SqlDbType.Char;
                usernameParameter.SqlValue = t.UserName;
                usernameParameter.ParameterName = "@USER";

                SqlParameter passwordParameter = new SqlParameter();
                passwordParameter.SqlDbType = SqlDbType.Char;
                passwordParameter.SqlValue = t.Password;
                passwordParameter.ParameterName = "@PASS";

                SqlParameter companyNameParameter = new SqlParameter();
                companyNameParameter.SqlDbType = SqlDbType.Char;
                companyNameParameter.SqlValue = t.AirlineName;
                companyNameParameter.ParameterName = "@NAME";

                SqlParameter originCountryParameter = new SqlParameter();
                originCountryParameter.SqlDbType = SqlDbType.Char;
                originCountryParameter.SqlValue = t.OriginCountry;
                originCountryParameter.ParameterName = "@CODE";

                SqlParameter idParameter = new SqlParameter();
                idParameter.SqlDbType = SqlDbType.Int;
                idParameter.SqlValue = t.Id;
                idParameter.ParameterName = "@ID";

                sqlCommand.Parameters.Add(usernameParameter);
                sqlCommand.Parameters.Add(passwordParameter);
                sqlCommand.Parameters.Add(companyNameParameter);
                sqlCommand.Parameters.Add(originCountryParameter);
                sqlCommand.Parameters.Add(idParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                connection.Close();
            }
        }
    }
}
