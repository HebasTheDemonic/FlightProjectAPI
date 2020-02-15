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
    class CustomerDAOMSSQL : ICustomerDAO
    {
        public void Add(Customer t)
        {
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "ADD_CUSTOMER";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter usernameParameter = new SqlParameter();
                usernameParameter.SqlDbType = SqlDbType.Char;
                usernameParameter.SqlValue = t.UserName;
                usernameParameter.ParameterName = "@USER";

                SqlParameter passwordParameter = new SqlParameter();
                passwordParameter.SqlDbType = SqlDbType.Char;
                passwordParameter.SqlValue = t.Password;
                passwordParameter.ParameterName = "@PASS";

                SqlParameter firstNameParameter = new SqlParameter();
                firstNameParameter.SqlDbType = SqlDbType.Char;
                firstNameParameter.SqlValue = t.FirstName;
                firstNameParameter.ParameterName = "@FIRST";

                SqlParameter lastNameParameter = new SqlParameter();
                lastNameParameter.SqlDbType = SqlDbType.Char;
                lastNameParameter.SqlValue = t.LastName;
                lastNameParameter.ParameterName = "@LAST";

                SqlParameter addressParameter = new SqlParameter();
                addressParameter.SqlDbType = SqlDbType.Char;
                addressParameter.SqlValue = t.Address;
                addressParameter.ParameterName = "@ADDRESS";

                SqlParameter phoneNumberParameter = new SqlParameter();
                phoneNumberParameter.SqlDbType = SqlDbType.Int;
                phoneNumberParameter.SqlValue = t.PhoneNo;
                phoneNumberParameter.ParameterName = "@PHONE";

                SqlParameter creditCardParameter = new SqlParameter();
                creditCardParameter.SqlDbType = SqlDbType.Int;
                creditCardParameter.SqlValue = t.PhoneNo;
                creditCardParameter.ParameterName = "@CREDIT";

                sqlCommand.Parameters.Add(usernameParameter);
                sqlCommand.Parameters.Add(passwordParameter);
                sqlCommand.Parameters.Add(firstNameParameter);
                sqlCommand.Parameters.Add(lastNameParameter);
                sqlCommand.Parameters.Add(addressParameter);
                sqlCommand.Parameters.Add(phoneNumberParameter);
                sqlCommand.Parameters.Add(creditCardParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                connection.Close();
            }
        }

        public int DoesCustomerExist(Customer customer)
        {
            int result = 0;
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "DOES_CUSTOMER_EXIST";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter usernameParameter = new SqlParameter();
                usernameParameter.SqlDbType = SqlDbType.Char;
                usernameParameter.SqlValue = customer.UserName;
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

        public Customer Get(int id)
        {
            Customer customer = new Customer();

            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_CUSTOMER_BY_ID";
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
                    customer = new Customer((int)sqlDataReader["ID"],
                                            (string)sqlDataReader["FIRST"],
                                            (string)sqlDataReader["LAST"],
                                            (string)sqlDataReader["USER"],
                                            (string)sqlDataReader["PASS"],
                                            (string)sqlDataReader["ADDRESS"],
                                            (int)sqlDataReader["PHONE"],
                                            (int)sqlDataReader["CARD"]);
                }
                connection.Close();
            }
            return customer;
        }

        public IList<Customer> GetAll()
        {
            List<Customer> customers = new List<Customer>();

            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_ALL_CUSTOMERS";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                while (sqlDataReader.Read() == true)
                {
                    Customer customer = new Customer((int)sqlDataReader["ID"],
                                            (string)sqlDataReader["FIRST"],
                                            (string)sqlDataReader["LAST"],
                                            (string)sqlDataReader["USER"],
                                            (string)sqlDataReader["PASS"],
                                            (string)sqlDataReader["ADDRESS"],
                                            (int)sqlDataReader["PHONE"],
                                            (int)sqlDataReader["CARD"]);
                    customers.Add(customer);
                }
                connection.Close();
            }
            return customers;
        }

        public Customer GetCustomerByUsername(string userName)
        {
            Customer customer = new Customer();

            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "GET_CUSTOMER_BY_USERNAME";
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
                    customer = new Customer((int)sqlDataReader["ID"],
                                            (string)sqlDataReader["FIRST"],
                                            (string)sqlDataReader["LAST"],
                                            (string)sqlDataReader["USER"],
                                            (string)sqlDataReader["PASS"],
                                            (string)sqlDataReader["ADDRESS"],
                                            (int)sqlDataReader["PHONE"],
                                            (int)sqlDataReader["CARD"]);
                }
                connection.Close();
            }
            return customer;
        }

        public void Remove(Customer t)
        {
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "REMOVE_CUSTOMER";
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

        public void Update(Customer t)
        {
            using (SqlConnection connection = new SqlConnection(ConfigurationManager.ConnectionStrings["GCloudConnectionString"].ConnectionString))
            {
                SqlCommand sqlCommand = new SqlCommand();
                sqlCommand.Connection = connection;
                sqlCommand.CommandText = "UPDATE_CUSTOMER";
                sqlCommand.CommandType = CommandType.StoredProcedure;

                SqlParameter idParameter = new SqlParameter();
                idParameter.SqlDbType = SqlDbType.Int;
                idParameter.SqlValue = t.Id;
                idParameter.ParameterName = "@ID";

                SqlParameter usernameParameter = new SqlParameter();
                usernameParameter.SqlDbType = SqlDbType.Char;
                usernameParameter.SqlValue = t.UserName;
                usernameParameter.ParameterName = "@USER";

                SqlParameter passwordParameter = new SqlParameter();
                passwordParameter.SqlDbType = SqlDbType.Char;
                passwordParameter.SqlValue = t.Password;
                passwordParameter.ParameterName = "@PASS";

                SqlParameter firstNameParameter = new SqlParameter();
                firstNameParameter.SqlDbType = SqlDbType.Char;
                firstNameParameter.SqlValue = t.FirstName;
                firstNameParameter.ParameterName = "@FIRST";

                SqlParameter lastNameParameter = new SqlParameter();
                lastNameParameter.SqlDbType = SqlDbType.Char;
                lastNameParameter.SqlValue = t.LastName;
                lastNameParameter.ParameterName = "@LAST";

                SqlParameter addressParameter = new SqlParameter();
                addressParameter.SqlDbType = SqlDbType.Char;
                addressParameter.SqlValue = t.Address;
                addressParameter.ParameterName = "@ADDRESS";

                SqlParameter phoneNumberParameter = new SqlParameter();
                phoneNumberParameter.SqlDbType = SqlDbType.Int;
                phoneNumberParameter.SqlValue = t.PhoneNo;
                phoneNumberParameter.ParameterName = "@PHONE";

                SqlParameter creditCardParameter = new SqlParameter();
                creditCardParameter.SqlDbType = SqlDbType.Int;
                creditCardParameter.SqlValue = t.CreditCardNumber;
                creditCardParameter.ParameterName = "@CARD";

                sqlCommand.Parameters.Add(idParameter);
                sqlCommand.Parameters.Add(usernameParameter);
                sqlCommand.Parameters.Add(passwordParameter);
                sqlCommand.Parameters.Add(firstNameParameter);
                sqlCommand.Parameters.Add(lastNameParameter);
                sqlCommand.Parameters.Add(addressParameter);
                sqlCommand.Parameters.Add(phoneNumberParameter);
                sqlCommand.Parameters.Add(creditCardParameter);

                connection.Open();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();
                connection.Close();
            }
        }
    }
}
