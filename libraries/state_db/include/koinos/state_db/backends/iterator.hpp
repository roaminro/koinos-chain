#pragma once

#include <koinos/state_db/backends/iterator.hpp>

#include <string>

namespace koinos::state_db::backends {

namespace detail {
   using value_type = std::string;
} // detail

class iterator;

class abstract_iterator
{
   public:
      using value_type = detail::value_type;

      virtual ~abstract_iterator() {};

      virtual const value_type& operator*()const = 0;

      virtual abstract_iterator& operator++() = 0;
      virtual abstract_iterator& operator--() = 0;

   private:
      friend class iterator;

      virtual bool valid()const = 0;
      virtual std::unique_ptr< abstract_iterator > copy()const = 0;
};

class iterator final
{
   public:
      using value_type = detail::value_type;

      iterator( std::unique_ptr< abstract_iterator > );
      iterator( const iterator& other );
      iterator( iterator&& other );

      const value_type& operator*()const;
      const value_type* operator->()const;

      iterator& operator++();
      iterator& operator--();

      iterator& operator=( const iterator& other );
      iterator& operator=( iterator&& other );

      friend bool operator==( const iterator& x, const iterator& y );
      friend bool operator!=( const iterator& x, const iterator& y );

   private:
      bool valid()const;

      std::unique_ptr< abstract_iterator > _itr;
};

} // koinos::state_db::backends
