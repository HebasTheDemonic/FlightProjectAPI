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
    internal class AdministratorDAO : IAdministratorDAO
    {
        const string CONNECTIONSTRING = ConnectionStrings.MSSQLConnectionString;

        public void Add(Administrator t)
        {
            using (SqlConnection connection = new SqlConnection(CONNECTIONSTRING))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "ADD_ADMINISTRATOR";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter usernameParameter = new SqlParameter();
                usernameParameter.SqlDbType = SqlDbType.Char;
                usernameParameter.SqlValue = t.UserName;
                usernameParameter.ParameterName = "@USER";

                SqlParameter passwordParameter = new SqlParameter();
                passwordParameter.SqlDbType = SqlDbType.Char;
                passwordParameter.SqlValue = t.Password;
                passwordParameter.ParameterName = "@PASS";

                sqlCommand.Parameters.Add(usernameParameter);
                sqlCommand.Parameters.Add(passwordParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                connection.Close();
            }
        }

        public int DoesAdministratorExist(Administrator administrator)
        {
            int result = 0;
            using (SqlConnection connection = new SqlConnection(CONNECTIONSTRING))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "DOES_ADMINISTRATOR_EXIST";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter usernameParameter = new SqlParameter();
                usernameParameter.SqlDbType = SqlDbType.Char;
                usernameParameter.SqlValue = administrator.UserName;
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

        public Administrator Get(int id)
        {
            Administrator administrator = new Administrator();
            using (SqlConnection connection = new SqlConnection(CONNECTIONSTRING))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_ADMINISTRATOR_BY_ID";
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
                    administrator = new Administrator((int)sqlDataReader["ID"],
                                                      (string)sqlDataReader["USER"],
                                                      (string)sqlDataReader["PASS"]);
                }
                connection.Close();
            }
            return administrator;
        }

        public Administrator GetAdministratorByUsername(string username)
        {
            Administrator administrator = new Administrator();

            using (SqlConnection connection = new SqlConnection(CONNECTIONSTRING))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_ADMINISTRATOR_BY_USERNAME";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter usernameParameter = new SqlParameter();
                usernameParameter.SqlDbType = SqlDbType.Char;
                usernameParameter.SqlValue = username;
                usernameParameter.ParameterName = "@USER";

                sqlCommand.Parameters.Add(usernameParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    administrator = new Administrator((int)sqlDataReader["ID"],
                                                     (string)sqlDataReader["USER"],
                                                     (string)sqlDataReader["PASS"]);
                }
                connection.Close();
            }
            return administrator;
        }

        public IList<Administrator> GetAll()
        {
            List<Administrator> administrators = new List<Administrator>();

            using (SqlConnection connection = new SqlConnection(CONNECTIONSTRING))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_ALL_ADMINISTRATORS";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    Administrator administrator = new Administrator((int)sqlDataReader["ID"],
                                                                    (string)sqlDataReader["USER"],
                                                                    (string)sqlDataReader["PASS"]);
                    administrators.Add(administrator);
                }
                connection.Close();
            }
            return administrators;
        }

        public void Remove(Administrator t)
        {
            using (SqlConnection connection = new SqlConnection(CONNECTIONSTRING))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "REMOVE_ADMINISTRATOR";
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

        public void Update(Administrator t)
        {
            using (SqlConnection connection = new SqlConnection(CONNECTIONSTRING))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "UPDATE_ADMINISTRATOR";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter usernameParameter = new SqlParameter();
                usernameParameter.SqlDbType = SqlDbType.Char;
                usernameParameter.SqlValue = t.UserName;
                usernameParameter.ParameterName = "@USER";

                SqlParameter passwordParameter = new SqlParameter();
                passwordParameter.SqlDbType = SqlDbType.Char;
                passwordParameter.SqlValue = t.Password;
                passwordParameter.ParameterName = "@PASS";

                SqlParameter idParameter = new SqlParameter();
                idParameter.SqlDbType = SqlDbType.Int;
                idParameter.SqlValue = t.Id;
                idParameter.ParameterName = "@ID";


                sqlCommand.Parameters.Add(usernameParameter);
                sqlCommand.Parameters.Add(passwordParameter);
                sqlCommand.Parameters.Add(idParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                connection.Close();
            }
        }
    }
}
