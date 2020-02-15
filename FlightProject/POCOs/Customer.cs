using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FlightProject.Exceptions;

namespace FlightProject.POCOs
{
    public class Customer : User, IPoco
    {
        public int Id { get; }
        public string FirstName { get; }
        public string LastName { get; }
        public string Address { get; }
        public int PhoneNo { get; }
        public int CreditCardNumber { get; }

        public Customer()
        {

        }

        public Customer(string userName, string password)
        {

        }

        public Customer(string firstName, string lastName, string userName, string password, string address, int phoneNo, int creditCardNumber) : this(userName, password)
        {
            FirstName = firstName ?? throw new ArgumentNullException(nameof(firstName));
            LastName = lastName ?? throw new ArgumentNullException(nameof(lastName));
            Address = address ?? throw new ArgumentNullException(nameof(address));
            PhoneNo = phoneNo;
            CreditCardNumber = creditCardNumber;
        }

        internal Customer(int iD, string firstName, string lastName, string userName, string password, string address, int phoneNo, int creditCardNumber) : this(firstName, lastName, userName, password, address, phoneNo, creditCardNumber)
        {
            Id = iD;
        }

        public static bool operator ==(Customer customer, Customer customer1) => customer.Equals(customer1);

        public static bool operator !=(Customer customer, Customer customer1) => !(customer == customer1);

        public override bool Equals(object obj)
        {
            var customer = obj as Customer;
            if (UserName == null || customer.UserName == null)
            {
                throw new CorruptedDataException();
            }
            return customer != null &&
                   UserName == customer.UserName;
        }

        public override int GetHashCode()
        {
            return 3000000 + Id.GetHashCode();
        }
    }
}
